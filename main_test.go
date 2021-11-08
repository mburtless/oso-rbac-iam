package main

import (
	"context"
	"fmt"
	"github.com/mburtless/oso-rbac-iam/datastore"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/sqlboiler/v4/types"
	"go.uber.org/zap"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

func Test_setup(t *testing.T) {
	l := zap.NewNop()
	defer l.Sync()
	logger = l.Sugar()

	tests := []struct {
		name    string
		route   string
		method  string
		apiKey  string
		expErr  bool
		expCode int
		expBody string
	}{
		{
			name:    "view valid zone",
			route:   "/zone/0",
			method:  "GET",
			apiKey:  "john",
			expErr:  false,
			expCode: 200,
			expBody: "<h1>A Repo</h1><p>Welcome john to zone foo.com</p>",
		},
		{
			name:    "view nonexistant zone",
			route:   "/zone/5",
			method:  "GET",
			apiKey:  "john",
			expErr:  false,
			expCode: 404,
			expBody: errHTMLZoneNotFound,
		},
		{
			name:   "view zone without authz",
			route:  "/zone/0",
			method: "GET",
			apiKey: "bob",
			expErr: false,
			// TODO: change to 401
			expCode: 404,
			expBody: "<h1>Whoops!</h1><p>That zone was not found</p>",
		},
		{
			name:    "delete valid zone",
			route:   "/zone/0",
			method:  "DELETE",
			apiKey:  "bob",
			expErr:  false,
			expCode: 200,
			expBody: "<h1>A Repo</h1><p>Deleted zone foo.com</p>",
		},
		{
			name:   "delete zone without authz",
			route:  "/zone/0",
			method: "DELETE",
			apiKey: "john",
			expErr: false,
			// TODO: change to 401?
			expCode: 404,
			expBody: errHTMLZoneNotFound,
		},
	}
	if err := initOso(); err != nil {
		log.Fatalf("Failed to initialize Oso: %s", err.Error())
	}
	app := setup(&mock_datastore{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, tt.route, nil)
			req.Header.Set("x-api-key", tt.apiKey)
			res, err := app.Test(req, -1)

			assert.Equal(t, tt.expErr, err != nil)

			if !tt.expErr {
				assert.Equal(t, tt.expCode, res.StatusCode)
				body, err := ioutil.ReadAll(res.Body)
				assert.NoError(t, err)
				assert.Equal(t, tt.expBody, string(body))
			}
		})
	}
}

type mock_datastore struct {}

func (ds *mock_datastore) FindZoneByID(ctx context.Context, id int) (*models.Zone, error) {
	if id == 0 {
		return &models.Zone{
			ZoneID: 1,
			Name: "foo.com",
			ResourceName: "oso:0:zone/foo.com",
			OrgID: 0,
		}, nil
	}
	return nil, fmt.Errorf("zone not found")
}

func (ds *mock_datastore) ListZonesByOrgID(ctx context.Context, orgID int) (*models.ZoneSlice, error) {
	return nil, nil
}

func (ds *mock_datastore) FindUserByKey(ctx context.Context, key string) (*models.User, error) {
	switch key {
	case "john":
		return &models.User{
			UserID: 1,
			Name: "john",
			APIKey: "john",
			OrgID: 0,
		}, nil
	case "bob":
		return &models.User{
			UserID: 2,
			Name: "bob",
			APIKey: "bob",
			OrgID: 0,
		}, nil
	}

	return nil, fmt.Errorf("user not found")
}

func (ds *mock_datastore) GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error) {
	return nil, nil
}

func (ds *mock_datastore) GetUserRolesAndPolicies(ctx context.Context, userID int) ([]*datastore.DenormalizedRole, error) {
	switch userID {
	case 1:
		return []*datastore.DenormalizedRole{
			{
				Role: models.Role{RoleID: 1, Name: "viewZonesRole", OrgID: 0},
				Policy: models.Policy{
					PolicyID: 1, Name: "viewZonesPolicy", Effect: "allow", Actions: types.StringArray{"view"}, ResourceName: "oso:0:zone/*"},
			},
		}, nil
	case 2:
		return []*datastore.DenormalizedRole{
			{
				Role: models.Role{RoleID: 1, Name: "deleteZonesRole", OrgID: 0},
				Policy: models.Policy{
					PolicyID: 1, Name: "deleteZonesPolicy", Effect: "allow", Actions: types.StringArray{"delete"}, ResourceName: "oso:0:zone/*"},
			},
		}, nil
	}

	return nil, fmt.Errorf("role not found for user")
}
