package main

//go:generate sqlboiler --wipe psql

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/mburtless/oso-rbac-iam/datastore"
	"go.uber.org/zap"
	"log"
	"reflect"
	"strconv"

	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"github.com/osohq/go-oso"
)

var osoClient oso.Oso
var logger *zap.SugaredLogger

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

func setup(ds datastore.Datastore) *fiber.App {
	app := fiber.New()
	app.Get("/zone/:zoneId", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		zoneId, err := strconv.Atoi(c.Params("zoneId"))
		if err != nil {
			return c.SendStatus(400)
		}
		return authorizeZoneRoute(c, ds, zoneId, "view")
	})

	app.Delete("/zone/:zoneId", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		zoneId, err := strconv.Atoi(c.Params("zoneId"))
		if err != nil {
			return c.SendStatus(400)
		}
		return authorizeZoneRoute(c, ds, zoneId, "delete")
	})
	return app
}

func initOso() error {
	var err error
	osoClient, err = oso.NewOso()
	if err != nil {
		return err
	}

	osoClient.RegisterClass(reflect.TypeOf(Zone{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(User{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(Role{}), nil)
	osoClient.RegisterClass(reflect.TypeOf(Policy{}), nil)
	if err := osoClient.RegisterClass(reflect.TypeOf(PolicyResourceName("foo")), nil); err != nil {
		return err
	}

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

func authorizeZoneRoute(c *fiber.Ctx, ds datastore.Datastore, zoneId int, action string) error {
	//z, err := GetZoneById(zoneId)
	// Get with no data filter
	z, err := ds.FindZoneByID(context.Background(), zoneId)
	if err != nil {
		return c.Status(404).SendString(fmt.Sprintf("<h1>Whoops!<h1><p>%s</p>", err.Error()))
	}

	apiKey := c.Get("x-api-key", "")
	//u, err := GetCurrentUser(apiKey)
	//u, err := models.Users(qm.Where("api_key = ?", apiKey)).One(context.Background(), db)
	u, err := ds.FindUserByKey(context.Background(), apiKey)
	if err != nil {
		return c.Status(401).SendString(fmt.Sprintf("<h1>Whoops!<h1><p>%s</p>", err.Error()))
	}

	err = osoClient.Authorize(u, action, z)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return c.Status(404).SendString("<h1>Whoops!</h1><p>That zone was not found</p>")
	}

	return c.Status(200).SendString(fmt.Sprintf("<h1>A Repo</h1><p>Welcome %s to zone %s</p>", u.Name, z.Name))
}
