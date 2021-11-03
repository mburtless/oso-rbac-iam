package datastore

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/gobwas/glob"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"github.com/volatiletech/sqlboiler/v4/types"
	"go.uber.org/zap"
	"strings"
)

var (
	errBadResourceID   = fmt.Errorf("improperly formatted resource ID")
	errBadResourceName = fmt.Errorf("improperly formated resource name")
)

type Datastore struct {
	db *sql.DB
	logger *zap.SugaredLogger
}

// DenormalizedRole is the combination of a role and one of it's policies
type DenormalizedRole struct {
	models.Role `boil:",bind"`
	models.Policy `boil:",bind"`
}

// converts a slice of denormalized roles into a map of derived roles
func toDerivedRoleMap(denormRoles []*DenormalizedRole) map[int]*DerivedRole {
	derivedRoles := map[int]*DerivedRole{}
	if len(denormRoles) == 0 {
		return derivedRoles
	}
	for _, denormRole := range denormRoles {
		// check if derived role already exists at index
		if _, ok := derivedRoles[denormRole.Role.RoleID]; !ok {
			// if not, populate it with current role
			derivedRoles[denormRole.Role.RoleID] = &DerivedRole{
				Role: denormRole.Role,
				Policies: []*RolePolicy{},
			}
		}
		// append policy
		derivedRoles[denormRole.Role.RoleID].Policies = append(derivedRoles[denormRole.Role.RoleID].Policies, toPolicy(&denormRole.Policy))
	}
	return derivedRoles
}

// DerivedRole is the combination of a role and all of it's policies
type DerivedRole struct {
	models.Role
	Policies []*RolePolicy
}

// RolePolicy resource
type RolePolicy struct {
	Effect     string
	Actions    []string
	Resource   PolicyResourceName
	Conditions types.StringArray
}

func toPolicy(policy *models.Policy) *RolePolicy {
	return &RolePolicy{
		Effect: policy.Effect,
		Actions: policy.Actions,
		Resource: PolicyResourceName(policy.ResourceName),
		Conditions: policy.Conditions,
	}
}

// Condition modifier for policies
type Condition struct {
	Type  string
	Value interface{}
}
// PolicyResourceName is a resource name modifier for use in Policies
type PolicyResourceName string

// ContainsResourceName checks if policy resource name contains given resource name
func (prn PolicyResourceName) ContainsResourceName(rn string) bool {
	orgIDinPRN, rIDinPRN, err := SplitResourceName(string(prn))
	if err != nil {
		return false
	}
	orgIDinRN, rIDinRN, err := SplitResourceName(rn)
	if err != nil {
		return false
	}
	// match on org id
	if orgIDinPRN != "*" && orgIDinPRN != orgIDinRN {
		return false
	}
	// match on resource ID
	g, _ := glob.Compile(rIDinPRN)
	return g.Match(rIDinRN)
}

// GetType returns resource type in resource's NRN
func (prn PolicyResourceName) GetType() (string, error) {
	rID, err := prn.GetResourceID()
	if err != nil {
		return "", err
	}
	t := strings.Split(rID, "/")
	if len(t) < 2 {
		return "", errBadResourceID
	}
	return t[0], nil
}

// IsType returns true if resource is given type t
func (prn PolicyResourceName) IsType(t string) bool {
	rType, err := prn.GetType()
	if err != nil {
		return false
	}
	return rType == t
}

func (prn PolicyResourceName) GetResourceID() (string, error) {
	_, rID, err := SplitResourceName(string(prn))
	if err != nil {
		return "", err
	}
	return rID, nil
}

// SplitResourceName splits a resource name into org ID and resource ID
func SplitResourceName(nrn string) (orgID string, rID string, err error) {
	s := strings.Split(nrn, ":")
	if len(s) != 3 {
		return "", "", errBadResourceName
	}
	return s[1], s[2], nil
}
func NewDatastore(db *sql.DB, l *zap.SugaredLogger) Datastore {
	return Datastore{db: db, logger: l}
}

func (ds *Datastore) FindZoneByID(ctx context.Context, id int) (*models.Zone, error) {
	z, err := models.FindZone(ctx, ds.db, id)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found zone in PG", "zone", z)
	return z, nil
}

func (ds *Datastore) FindUserByKey(ctx context.Context, key string) (*models.User, error) {
	u, err := models.Users(qm.Where("api_key = ?", key)).One(ctx, ds.db)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found requester in PG", "user", u)
	return u, nil
}

func (ds *Datastore) GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error) {
	roles, err := user.Roles().All(ctx, ds.db)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found roles for user", "roles", roles)
	return roles, nil
}

func (ds *Datastore) GetUserRolesAndPolicies(ctx context.Context, userID int) (map[int]*DerivedRole, error) {
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
	drs := toDerivedRoleMap(dr)
	ds.logger.Debugw("found derived roles for user", "roles", drs)
	return drs, nil
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
