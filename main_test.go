package main

import (
	"context"
	"fmt"
	"github.com/lucasepe/codename"
	"github.com/mburtless/oso-rbac-iam/datastore"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/mburtless/oso-rbac-iam/pkg/roles"
	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/sqlboiler/v4/types"
	"go.uber.org/zap"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

func newNopLog() *zap.SugaredLogger {
	l := zap.NewNop()
	defer l.Sync()
	return l.Sugar()
}

func Test_setup(t *testing.T) {
	logger = newNopLog()

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
	app := setup(&mockDatastore{})

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

func benchmarkAuthz(b *testing.B, roles []*datastore.DenormalizedRole) {
	// test single role with many policies attached
	// generate many roles with single policy attached
	logger = newNopLog()

	if err := initOso(); err != nil {
		log.Fatalf("Failed to initialize Oso: %s", err.Error())
	}

	ds := newBenchDatastore(roles)
	//b.Logf("roles in datastore:\n%s", ds.denormRoles)

	app := setup(ds)

	// reset timer to ignore init time
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		// submit req that executes oso policy against roles and policies in datastore
		req, err := http.NewRequest("GET", "/zone/0", nil)
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("x-api-key", "bob")
		app.Test(req, -1)
	}
}

func Benchmark_MultiplePolicyNoAuthz(b *testing.B) {
	tests := []int{10, 100, 500, 1000}
	for _, t := range tests{
		b.Run(fmt.Sprintf("%d policies", t), func(b *testing.B) {
			// gen denorm roles with given number of policies
			roles, err := genSingleRoleManyPolicies(t)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkAuthz(b, roles)
		})
	}
}

func Benchmark_MultiplePolicyWithAuthz(b *testing.B) {
	tests := []int{10, 100, 500, 1000}
	for _, t := range tests{
		b.Run(fmt.Sprintf("%d policies", t), func(b *testing.B) {
			// gen denorm roles with given number of policies
			roles, err := genSingleRoleManyPolicies(t-1)
			// append a role that allows authz
			roles = append(roles, &datastore.DenormalizedRole{
				Role: models.Role{RoleID: 1, Name: "viewZonesRole", OrgID: 0},
				Policy: models.Policy{
					PolicyID: t+1, Name: "viewZonesPolicy", Effect: "allow", Actions: types.StringArray{"view"}, ResourceName: "oso:0:zone/*"},
			})
			if err != nil {
				b.Fatal(err)
			}
			benchmarkAuthz(b, roles)
		})
	}
}


func Benchmark_MultipleRolesNoAuthz(b *testing.B) {
	tests := []int{10, 100, 500, 1000}
	for _, t := range tests {
		b.Run(fmt.Sprintf("%d roles", t), func(b *testing.B) {
			// gen denorm roles with given number of roles
			roles, err := genManyRolesSinglePolicy(t)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkAuthz(b, roles)
		})
	}
}

func Benchmark_MultipleRolesWithAuthz(b *testing.B) {
	tests := []int{10, 100, 500, 1000}
	for _, t := range tests {
		b.Run(fmt.Sprintf("%d roles", t), func(b *testing.B) {
			// gen denorm roles with given number of roles
			roles, err := genManyRolesSinglePolicy(t-1)
			if err != nil {
				b.Fatal(err)
			}
			roles = append(roles, &datastore.DenormalizedRole{
				Role: models.Role{RoleID: t+1, Name: "viewZonesRole", OrgID: 0},
				Policy: models.Policy{
					PolicyID: t+1, Name: "viewZonesPolicy", Effect: "allow", Actions: types.StringArray{"view"}, ResourceName: "oso:0:zone/*"},
			})
			benchmarkAuthz(b, roles)
		})
	}
}

// datastore for unit tests
type mockDatastore struct {}

func (ds *mockDatastore) FindZoneByID(ctx context.Context, id int) (*models.Zone, error) {
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

func (ds *mockDatastore) ListZonesByOrgID(ctx context.Context, orgID int) (*models.ZoneSlice, error) {
	return nil, nil
}

func (ds *mockDatastore) FindUserByKey(ctx context.Context, key string) (*models.User, error) {
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

func (ds *mockDatastore) GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error) {
	return nil, nil
}

func (ds *mockDatastore) GetUserRolesAndPolicies(ctx context.Context, userID int) ([]*datastore.DenormalizedRole, error) {
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


func (ds *mockDatastore) GetUserDerivedRoles(ctx context.Context, userID int) (map[int]*datastore.DerivedRole, error){
	switch userID {
	case 1:
		return map[int]*datastore.DerivedRole{
			1: {
				Role: models.Role{RoleID: 1, Name: "viewZonesRole", OrgID: 0},
				Policies: []*roles.RolePolicy{
					{
						Effect: "allow",
						Actions: []string{"view"},
						Resource: "oso:0:zone/*",
						Conditions: nil,
					},
				},
			},
		}, nil
	case 2:
		return map[int]*datastore.DerivedRole{
			1: {
				Role: models.Role{RoleID: 1, Name: "deleteZonesRole", OrgID: 0},
				Policies: []*roles.RolePolicy{
					{
						Effect: "allow",
						Actions: []string{"delete"},
						Resource: "oso:0:zone/*",
						Conditions: nil,
					},
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("role not found for user")
}

// datastore for benchmarks

// configures new datastore populated with given roles
func newBenchDatastore(denormRoles []*datastore.DenormalizedRole) *benchDatastore {
	return &benchDatastore{
		denormRoles: denormRoles,
		derivedRoles: datastore.ToDerivedRoleMap(denormRoles),
	}
}

type benchDatastore struct {
	denormRoles []*datastore.DenormalizedRole
	derivedRoles map[int]*datastore.DerivedRole
}

func (ds *benchDatastore) FindZoneByID(ctx context.Context, id int) (*models.Zone, error) {
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

func (ds *benchDatastore) ListZonesByOrgID(ctx context.Context, orgID int) (*models.ZoneSlice, error) {
	return nil, nil
}

func (ds *benchDatastore) FindUserByKey(ctx context.Context, key string) (*models.User, error) {
	switch key {
	case "bob":
		return &models.User{
			UserID: 1,
			Name: "bob",
			APIKey: "bob",
			OrgID: 0,
		}, nil
	}

	return nil, fmt.Errorf("user not found")
}

func (ds *benchDatastore) GetUserRoles(ctx context.Context, user *models.User) (models.RoleSlice, error) {
	return nil, nil
}

func (ds *benchDatastore) GetUserRolesAndPolicies(ctx context.Context, userID int) ([]*datastore.DenormalizedRole, error) {
	switch userID {
	case 1:
		return ds.denormRoles, nil
	}

	return nil, fmt.Errorf("role not found for user")
}

func (ds *benchDatastore) GetUserDerivedRoles(ctx context.Context, userID int) (map[int]*datastore.DerivedRole, error){
	switch userID {
	case 1:
		return ds.derivedRoles, nil
	}

	return nil, fmt.Errorf("role not found for user")
}

// generates a single role with many policies attatched
func genSingleRoleManyPolicies(numPolicies int) ([]*datastore.DenormalizedRole, error) {
	var denormRoles []*datastore.DenormalizedRole
	role := models.Role{RoleID: 1, Name: "singleRoleManyPolicies", OrgID: 0}
	rng, err := codename.DefaultRNG()
	if err != nil {
		return nil, err
	}

	for i := 0; i < numPolicies; i++ {
		name := codename.Generate(rng, 0)
		denormRoles = append(denormRoles, &datastore.DenormalizedRole{Role: role, Policy: genPolicy(name, i)})
	}

	return denormRoles, nil
}

// generates multiples roles with a single policy
func genManyRolesSinglePolicy(numRoles int) ([]*datastore.DenormalizedRole, error) {
	var denormRoles []*datastore.DenormalizedRole
	rng, err := codename.DefaultRNG()
	if err != nil {
		return nil, err
	}

	for i := 0; i < numRoles; i++ {
		name := codename.Generate(rng, 0)
		role := models.Role{RoleID: i, Name: fmt.Sprintf("role-%s", name), OrgID: 0}
		denormRoles = append(denormRoles, &datastore.DenormalizedRole{Role: role, Policy: genPolicy(name, i)})
	}
	return denormRoles, nil
}

// genPolicy generates a policy with a given name N and ID that has view access to zone N.com
func genPolicy(policyName string, policyId int) models.Policy {
	resourceName := fmt.Sprintf("oso:0:zone/%s.com", policyName)
	return models.Policy{
		PolicyID: policyId,
		Name: policyName,
		Effect: "allow",
		Actions: types.StringArray{"view"},
		ResourceName: resourceName,
	}
}