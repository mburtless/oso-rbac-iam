package main

import (
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/mburtless/oso-rbac-iam/datastore"
	"github.com/mburtless/oso-rbac-iam/models"
	"strconv"
	"strings"
)

var (
	errHTMLZoneNotFound  = "<h1>Whoops!</h1><p>That zone was not found</p>"
	errHTMLZonesNotFound = "<h1>Whoops!</h1><p>No zones found in org</p>"
	errHTMLUserNotFound  = "<h1>Whoops!<h1><p>User not found</p>"
)

// doesn't actually delete zone from DS, just simulates to test authz call
func deleteZoneRoute(c *fiber.Ctx, ds datastore.Datastore) error {
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
	// get zone
	z, err := getReqZone(c, ds)
	if err != nil {
		return c.Status(404).SendString("<h1>Whoops!</h1><p>That zone was not found</p>")
	}

	// get requester from user context
	reqUser, err := getReqMeta(c)
	if err != nil {
		return c.Status(401).SendString("<h1>Whoops!<h1><p>User not found</p>")
	}

	if err := authorizeZoneRoute(reqUser, "delete", z); err != nil {
		return c.Status(404).SendString("<h1>Whoops!</h1><p>That zone was not found</p>")
	}
	return c.Status(200).SendString(fmt.Sprintf("<h1>A Repo</h1><p>Deleted zone %s</p>", z.Name))
}

func getZoneRoute(c *fiber.Ctx, ds datastore.Datastore) error {
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
	// get zone
	z, err := getReqZone(c, ds)
	if err != nil {
		return c.Status(404).SendString(errHTMLZoneNotFound)
	}

	// get requester from user context
	reqUser, err := getReqMeta(c)
	if err != nil {
		return c.Status(401).SendString(errHTMLUserNotFound)
	}

	if err := authorizeZoneRoute(reqUser, "view", z); err != nil {
		return c.Status(404).SendString(errHTMLZoneNotFound)
	}
	return c.Status(200).SendString(fmt.Sprintf("<h1>A Repo</h1><p>Welcome %s to zone %s</p>", reqUser.User.Name, z.Name))
}

func listZonesRoute(c *fiber.Ctx, ds datastore.Datastore) error {
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
	// get all zones in org
	reqUser, err := getReqMeta(c)
	if err != nil {
		return c.Status(401).SendString(errHTMLUserNotFound)
	}
	zs, err := ds.ListZonesByOrgID(context.Background(), reqUser.User.OrgID)
	if err != nil {
		logger.Errorw("error listing zones for org", "orgID", reqUser.User.OrgID, "error", err)
		return c.Status(404).SendString(errHTMLZonesNotFound)
	}

	var zoneNames []string
	for _, z := range *zs {
		zoneNames = append(zoneNames, z.Name)
	}
	return c.Status(200).SendString(fmt.Sprintf("<h1>A Repo</h1><p>%s</p>", strings.Join(zoneNames, ",")))
}

// gets the zone requested in zoneId param
func getReqZone(c *fiber.Ctx, ds datastore.Datastore) (*models.Zone, error) {
	zoneId, err := strconv.Atoi(c.Params("zoneId"))
	if err != nil {
		return nil, errMissingZoneId
	}
	z, err := ds.FindZoneByID(context.Background(), zoneId)
	if err != nil {
		logger.Errorw("error finding zone by ID", "error", err)
		return nil, err
	}
	return z, nil
}

func authorizeZoneRoute(u *DerivedUser, action string, z *models.Zone) error {
	err := osoClient.Authorize(u, action, z)
	if err != nil {
		logger.Errorw("error authorizing request", "error", err)
		return err
	}

	return nil
}
