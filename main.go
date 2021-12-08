package main

//go:generate sqlboiler --wipe psql

import (
	"database/sql"
	"errors"
	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"github.com/mburtless/oso-rbac-iam/datastore"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/mburtless/oso-rbac-iam/pkg/matchers"
	"github.com/mburtless/oso-rbac-iam/pkg/roles"
	"github.com/osohq/go-oso"
	"go.uber.org/zap"
	"log"
	"reflect"
)

var (
	osoClient        oso.Oso
	logger           *zap.SugaredLogger
	errMissingZoneId = errors.New("zoneId not found in request params")
	errMissingAPIKey = errors.New("x-api-key value not found in request headers")
)

func main() {
	l, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %s", err.Error())
	}
	defer l.Sync()
	logger = l.Sugar()

	if err := initOso(); err != nil {
		log.Fatalf("Failed to initialize Oso: %s", err.Error())
	}

	db, err := initPG()
	if err != nil {
		log.Fatalf("Failed to connect to PG: %s", err.Error())
	}
	defer db.Close()

	app := setup(datastore.NewDatastore(db, logger))

	if err := app.Listen(":5000"); err != nil {
		log.Fatalf("Failed to start: %s", err.Error())
	}
}

// setup configures routes
func setup(ds datastore.Datastore) *fiber.App {
	app := fiber.New()

	// Middleware
	app.Use(func(c *fiber.Ctx) error {
		return setReqMeta(c, ds)
	})

	// Endpoints
	app.Get("/user", func(c *fiber.Ctx) error {
		return listUsersRoute(c, ds)
	})

	app.Get("/zone/:zoneId", func(c *fiber.Ctx) error {
		return getZoneRoute(c, ds)
	})

	app.Get("/zone", func(c *fiber.Ctx) error {
		return listZonesRoute(c, ds)
	})

	app.Delete("/zone/:zoneId", func(c *fiber.Ctx) error {
		return deleteZoneRoute(c, ds)
	})
	return app
}

// initOso loads polar policy, registers resources and initializes Oso client singleton
func initOso() error {
	var err error
	osoClient, err = oso.NewOso()
	if err != nil {
		return err
	}

	// Register custom types with Oso core
	if err := osoClient.RegisterClass(reflect.TypeOf(roles.PolicyResourceName("foo")), nil); err != nil {
		return err
	}
	osoClient.RegisterClass(reflect.TypeOf(models.Zone{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(models.User{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(models.Role{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(models.Policy{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(roles.RolePolicy{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(datastore.EffectivePerms{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(DerivedUser{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(matchers.HasSuffix{}), nil)

	// Load Oso policy
	if err := osoClient.LoadFiles([]string{"iam.polar"}); err != nil {
		return err
	}
	return nil
}

func initPG() (*sql.DB, error) {
	db, err := sql.Open("postgres", `dbname=oso-rbac-iam host=localhost user=oso password=ososecretpwd sslmode=disable`)
	if err != nil {
		return nil, err
	}

	logger.Info("Connected to PG")
	return db, nil
}
