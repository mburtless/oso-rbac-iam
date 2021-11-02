package datastore

import (
	"context"
	"database/sql"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"go.uber.org/zap"
	"strings"
)

type Datastore struct {
	db *sql.DB
	logger *zap.SugaredLogger
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
