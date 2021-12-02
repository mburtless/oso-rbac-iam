package datastore

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/mburtless/oso-rbac-iam/pkg/roles"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"go.uber.org/zap"
	"strings"
)

type Datastore interface {
	FindZoneByID(ctx context.Context, id int) (*models.Zone, error)
	ListZonesByOrgID(ctx context.Context, orgID int) (*models.ZoneSlice, error)
	FindUserByKey(ctx context.Context, key string) (*models.User, error)
	GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error)
	GetUserRolesAndPolicies(ctx context.Context, userID int) ([]*DenormalizedRole, error)
	GetUserDerivedRoles(ctx context.Context, userID int) (DerivedRoles, error)
	GetEffectivePerms(ctx context.Context, userID int) (EffectivePerms, error)
}

type datastore struct {
	db *sql.DB
	logger *zap.SugaredLogger
}

func NewDatastore(db *sql.DB, l *zap.SugaredLogger) Datastore {
	return &datastore{db: db, logger: l}
}

func (ds *datastore) FindZoneByID(ctx context.Context, id int) (*models.Zone, error) {
	z, err := models.FindZone(ctx, ds.db, id)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found zone in PG", "zone", z)
	return z, nil
}

func (ds *datastore) ListZonesByOrgID(ctx context.Context, orgID int) (*models.ZoneSlice, error) {
	zs, err := models.Zones(qm.Where("org_id = ?", orgID)).All(ctx, ds.db)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found zones in PG", "zone", zs)
	return &zs, nil
}

func (ds *datastore) FindUserByKey(ctx context.Context, key string) (*models.User, error) {
	u, err := models.Users(qm.Where("api_key = ?", key)).One(ctx, ds.db)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found requester in PG", "user", u)
	return u, nil
}

func (ds *datastore) GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error) {
	r, err := user.Roles().All(ctx, ds.db)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found roles for user", "roles", r)
	return r, nil
}

func (ds *datastore) GetUserRolesAndPolicies(ctx context.Context, userID int) ([]*DenormalizedRole, error) {
	var dr []*DenormalizedRole
	err := models.NewQuery(
		qm.Select("role.*", "policy.*"),
		qm.From("user_roles"),
		qm.InnerJoin("role on user_roles.role_id = role.role_id"),
		qm.InnerJoin("role_policies on user_roles.role_id = role.role_id"),
		qm.InnerJoin("policy on role_policies.policy_id = policy.policy_id"),
		qm.And("user_roles.user_id = ?", userID),
		qm.And("role_policies.role_id = role.role_id"),
		).Bind(ctx, ds.db, &dr)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found denorm roles for user", "roles", dr)
	return dr, nil
}

// GetUserDerivedRoles returns derived set of roles and policies for a user
// Deprecated: use GetEffectivePerms instead
func (ds *datastore) GetUserDerivedRoles(ctx context.Context, userID int) (DerivedRoles, error){
	// load user's roles and policies
	drs, err := ds.GetUserRolesAndPolicies(ctx, userID)
	if err != nil {
		ds.logger.Errorw("error finding derived roles for user", "error", err)
		return nil, err
	}
	return ToDerivedRoleMap(drs), nil
}

func (ds *datastore) GetEffectivePerms(ctx context.Context, userID int) (EffectivePerms, error) {
	// load user's roles and policies
	drs, err := ds.GetUserRolesAndPolicies(ctx, userID)
	if err != nil {
		ds.logger.Errorw("error finding effective permissions for user", "error", err)
		return EffectivePerms{}, err
	}
	return ToEffectivePerms(drs), nil
}

// TODO: try to delete this by integrating matchers in a different way?
func toZone(z *models.Zone) *Zone {
	return &Zone{
		Id: z.ZoneID,
		Name: z.Name,
		Org: z.OrgID,
		ResourceName: z.ResourceName,
	}
}

// Zone resource
type Zone struct {
	Id           int
	Name         string
	Org          int
	ResourceName string
}

// SuffixMatch returns True if zone name has given suffix
func (z Zone) SuffixMatch(suffix string) bool {
	return strings.HasSuffix(z.Name, suffix)
}

type DerivedRole struct {
	models.Role
	Policies map[int]*roles.RolePolicy
}

func (dr DerivedRole) String() string {
	return fmt.Sprintf("Role: %v Policies: %v", dr.Role, dr.Policies)
}

type DerivedRoles map[int]*DerivedRole

// ToDerivedRoleMap converts a slice of denormalized roles into a map of derived roles
func ToDerivedRoleMap(denormRoles []*DenormalizedRole) DerivedRoles {
	derivedRoles := map[int]*DerivedRole{}
	if len(denormRoles) == 0 {
		return derivedRoles
	}
	for _, denormRole := range denormRoles {
		roleID := denormRole.Role.RoleID
		policyID := denormRole.PolicyID
		// check if derived role already exists at index
		if _, ok := derivedRoles[roleID]; !ok {
			// if not, populate it with current role
			derivedRoles[roleID] = &DerivedRole{
				Role:     denormRole.Role,
				Policies: map[int]*roles.RolePolicy{},
			}
		}
		// check if policy already exists in current role
		if _, ok := derivedRoles[roleID].Policies[policyID]; !ok {
			// if not populate policy and empty condition slice
			derivedRoles[roleID].Policies[policyID] = ToPolicy(&denormRole.Policy)
		}
		// if so, condition must be missing from policy.  Append it.
		if cond := ToCondition(denormRole.Condition); cond != nil {
			derivedRoles[roleID].Policies[policyID].Conditions = append(derivedRoles[roleID].Policies[policyID].Conditions, *cond)
		}
		//derivedRoles[denormRole.Role.RoleID].Policies = append(derivedRoles[denormRole.Role.RoleID].Policies, ToPolicy(&denormRole.Policy, &denormRole.Condition))
	}
	return derivedRoles
}

// DenormalizedRole is the combination of a role and one of it's policies
type DenormalizedRole struct {
	models.Role   `boil:",bind"`
	models.Policy `boil:",bind"`
	models.Condition `boil:",bind"`
}

func (dn DenormalizedRole) String() string {
	return fmt.Sprintf(
		"Role: (ID: %d Name: %s) Policy: (ID: %d Name: %s)",
		dn.RoleID, dn.Role.Name, dn.PolicyID, dn.Policy.Name,
	)
}

func ToCondition(cond models.Condition) *roles.Condition {
	// nil cond check
	if cond.ConditionID == 0 {
		return nil
	}
	return &roles.Condition{
		Type: cond.Type,
		Value: cond.Value,
	}
}

func ToPolicy(policy *models.Policy) *roles.RolePolicy {
	return &roles.RolePolicy{
		ID: 		policy.PolicyID,
		Effect:     policy.Effect,
		Actions:    policy.Actions,
		Resource:   roles.PolicyResourceName(policy.ResourceName),
		Conditions: []roles.Condition{},
	}
}

// ToEffectivePerms converts a slice of denormalized roles into a set of effective permissions
func ToEffectivePerms(denormRoles []*DenormalizedRole) EffectivePerms {
	perms := NewEffectivePerms()
	if len(denormRoles) == 0 {
		return EffectivePerms{}
	}

	for _, denormRole := range denormRoles {
		// convert policy
		p := ToPolicy(&denormRole.Policy)
		t, err := p.Resource.GetType()
		if err != nil {
			// invalid resource type, continue
			continue
		}
		// cache resource name in namespaces
		perms.Namespaces[t] = append(perms.Namespaces[t], string(p.Resource))
		// cache policy in appropriate policy store
		if p.Effect == "allow" {
			perms.AllowPolicies[string(p.Resource)] = append(perms.AllowPolicies[string(p.Resource)], p)
		} else if p.Effect == "deny" {
			perms.DenyPolicies[string(p.Resource)] = append(perms.DenyPolicies[string(p.Resource)], p)
		}
		// if effect type is unknown, continue
	}

	return perms
}

// NewEffectivePerms returns a set of effective perms with initialized slices
func NewEffectivePerms() EffectivePerms {
	return EffectivePerms{
		Namespaces: map[string][]string{},
		AllowPolicies: PoliciesByNamespace{},
		DenyPolicies: PoliciesByNamespace{},
	}
}

// EffectivePerms is the optimized set of namespaces and policies that are effective for a given entity
type EffectivePerms struct {
	// All namespaces in effective policies indexed by service type
	Namespaces map[string][]string
	// All allow policies in effective policies, indexed by namespace
	AllowPolicies PoliciesByNamespace
	// All deny policies in effective policies, indexed by namespace
	DenyPolicies PoliciesByNamespace
}

// PoliciesByNamespace is used to cache all policies, sorted by namespace they apply to
type PoliciesByNamespace map[string][]*roles.RolePolicy
