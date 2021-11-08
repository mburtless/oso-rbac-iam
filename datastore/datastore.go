package datastore

import (
	"context"
	"database/sql"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"go.uber.org/zap"
	"strings"
)



// DenormalizedRole is the combination of a role and one of it's policies
type DenormalizedRole struct {
	models.Role `boil:",bind"`
	models.Policy `boil:",bind"`
}

type Datastore interface {
	FindZoneByID(ctx context.Context, id int) (*models.Zone, error)
	ListZonesByOrgID(ctx context.Context, orgID int) (*models.ZoneSlice, error)
	FindUserByKey(ctx context.Context, key string) (*models.User, error)
	GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error)
	GetUserRolesAndPolicies(ctx context.Context, userID int) ([]*DenormalizedRole, error)
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
	roles, err := user.Roles().All(ctx, ds.db)
	if err != nil {
		return nil, err
	}
	ds.logger.Debugw("found roles for user", "roles", roles)
	return roles, nil
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
