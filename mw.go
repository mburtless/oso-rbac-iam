package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/mburtless/oso-rbac-iam/datastore"
	"github.com/mburtless/oso-rbac-iam/models"
)

type reqMetaKeyType string

const reqMetaKey reqMetaKeyType = "reqMetaKey"

var errMissingReqMeta = errors.New("request metadata not found in user context")

// DerivedUser is a user and all of it's roles and policies
type DerivedUser struct {
	User *models.User
	Roles map[int]*datastore.DerivedRole
}

// loads derived user associated with request and saves it in request metadata in user context
// for use in fine grained authorization within endpoint
func setReqMeta(c *fiber.Ctx, ds datastore.Datastore) error {
	var (
		reqMeta DerivedUser
		err     error
	)
	apiKey := c.Get("x-api-key", "")
	if apiKey == "" {
		return c.Status(401).SendString(fmt.Sprintf("<h1>Whoops!<h1><p>%s</p>", errMissingAPIKey))
	}

	// load user
	reqMeta.User, err = ds.FindUserByKey(context.Background(), apiKey)
	if err != nil {
		logger.Errorw("error finding user by api key", "error", err)
		return c.Status(401).SendString("<h1>Whoops!<h1><p>User not found</p>")
	}
	// load user's roles and policies
	/*drs, err := ds.GetUserRolesAndPolicies(context.Background(), reqMeta.User.UserID)
	if err != nil {
		logger.Errorw("error finding derived roles for user", "error", err)
		return c.Status(401).SendString("<h1>Whoops!<h1><p>User not found</p>")
	}
	reqMeta.Roles = datastore.ToDerivedRoleMap(drs)*/
	reqMeta.Roles, err = ds.GetUserDerivedRoles(context.Background(), reqMeta.User.UserID)
	if err != nil {
		logger.Errorw("error finding derived roles for user", "error", err)
		return c.Status(401).SendString("<h1>Whoops!<h1><p>User not found</p>")
	}
	logger.Debugw("found derived roles for user", "roles", reqMeta.Roles)

	// save to user context
	ctx := c.UserContext()
	ctx = context.WithValue(ctx, reqMetaKey, reqMeta)
	c.SetUserContext(ctx)

	return c.Next()
}

func getReqMeta(c *fiber.Ctx) (*DerivedUser, error) {
	reqMeta := c.UserContext().Value(reqMetaKey)
	if reqMeta == nil {
		return nil, errMissingReqMeta
	}
	rm, ok := reqMeta.(DerivedUser)
	if !ok {
		return nil, errors.New("invalid request metadata in user context")
	}
	return &rm, nil
}