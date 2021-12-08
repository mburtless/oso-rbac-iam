package datastore

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/mburtless/oso-rbac-iam/pkg/roles"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"go.uber.org/zap"
)

type Datastore interface {
	FindZoneByID(ctx context.Context, id int) (*models.Zone, error)
	ListZonesByOrgID(ctx context.Context, orgID int) (*models.ZoneSlice, error)
	ListUsersByOrgID(ctx context.Context, orgID int) (*models.UserSlice, error)
	FindUserByKey(ctx context.Context, key string) (*models.User, error)
	GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error)
	GetUserRolesAndPolicies(ctx context.Context, userID int) ([]*DenormalizedRole, error)
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

func (ds *datastore) ListUsersByOrgID(ctx context.Context, orgID int) (*models.UserSlice, error) {
	us, err := models.Users(qm.Where("org_id = ?", orgID)).All(ctx, ds.db)
	if err != nil {
		return nil, err
	}
	return &us, nil
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
	// TODO: optimize query for new EffectivePerms datastrucuture?
	err := models.NewQuery(
		qm.Select(
			"role.*",
			"policy.*",
			// account for nil vals due to left join
			"COALESCE(c.condition_id, 0) as condition_id",
			"COALESCE(c.type, '') as type",
			"COALESCE(c.value, '') as value"),
		qm.From("user_roles"),
		qm.InnerJoin("role on user_roles.role_id = role.role_id"),
		qm.InnerJoin("role_policies on user_roles.role_id = role.role_id"),
		qm.InnerJoin("policy on role_policies.policy_id = policy.policy_id"),
		qm.And("user_roles.user_id = ?", userID),
		qm.And("role_policies.role_id = role.role_id"),
		qm.LeftOuterJoin("condition_policies cp on policy.policy_id = cp.policy_id"),
		qm.LeftOuterJoin("condition c on c.condition_id = cp.condition_id"),
		).Bind(ctx, ds.db, &dr)
	if err != nil {
		return nil, err
	}


	ds.logger.Debugw("found denorm roles for user", "roles", dr)
	return dr, nil
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
		ID: cond.ConditionID,
	}
}

func ToPolicy(policy *models.Policy) *roles.RolePolicy {
	return &roles.RolePolicy{
		ID: 		policy.PolicyID,
		Effect:     policy.Effect,
		Actions:    policy.Actions,
		Resource:   roles.PolicyResourceName(policy.ResourceName),
		Conditions: map[int]*roles.Condition{},
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
		c := ToCondition(denormRole.Condition)

		// cache policy in appropriate policy store
		if p.Effect == "allow" {
			cachePolicy(perms.AllowPolicies, p, c)
		} else if p.Effect == "deny" {
			cachePolicy(perms.DenyPolicies, p, c)
		}
		// if effect type is unknown, ignore
	}

	return perms
}

func cachePolicy(policyCache PoliciesByNamespace, policy *roles.RolePolicy, cond *roles.Condition) {
	policyName := string(policy.Resource)
	// check if policy has already been cached for this namespace
	if _, ok := policyCache[policyName][policy.ID]; ok && cond != nil {
		// if so, condition must be missing.  Cache it.
		policyCache[policyName][policy.ID].Conditions[cond.ID] = cond
	} else {
		// if not, cache policy and condition, if applicable

		// init nil map
		if policyCache[policyName] == nil {
			policyCache[policyName]= map[int]*roles.RolePolicy{}
		}

		if cond != nil {
			policy.Conditions[cond.ID] = cond
		}

		policyCache[policyName][policy.ID] = policy
	}
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
type PoliciesByNamespace map[string]map[int]*roles.RolePolicy
