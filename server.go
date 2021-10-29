package main

import (
	"fmt"
	"log"
	"reflect"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/osohq/go-oso"
)

var osoClient oso.Oso

func main() {
	if err := initOso(); err != nil{
		log.Fatalf("Failed to initialize Oso: %s", err.Error())
	}

	app := setup()

	if err := app.Listen(":5000"); err != nil {
		log.Fatalf("Failed to start: %s", err.Error())
	}
}

func setup() *fiber.App {
	app := fiber.New()
	app.Get("/zone/:zoneId", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		zoneId, err := strconv.Atoi(c.Params("zoneId"))
		if err != nil {
			return c.SendStatus(400)
		}
		return authorizeZoneRoute(c, zoneId, "view")
	})

	app.Delete("/zone/:zoneId", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		zoneId, err := strconv.Atoi(c.Params("zoneId"))
		if err != nil {
			return c.SendStatus(400)
		}
		return authorizeZoneRoute(c, zoneId, "delete")
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

func authorizeZoneRoute(c *fiber.Ctx, zoneId int, action string) error {
	z, err := GetZoneById(zoneId)
	if err != nil {
		return c.Status(404).SendString(fmt.Sprintf("<h1>Whoops!<h1><p>%s</p>", err.Error()))
	}
	apiKey := c.Get("x-api-key", "")
	u, err := GetCurrentUser(apiKey)
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