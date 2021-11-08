package main

import (
	"github.com/mburtless/oso-rbac-iam/datastore"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/sqlboiler/v4/types"
	"reflect"
	"testing"
)

func TestPolicyResourceName_ContainsResourceName(t *testing.T) {
	tests := []struct {
		name               string
		policyResourceName PolicyResourceName
		resourceName       string
		exp                bool
	}{
		{
			name:               "exact match",
			policyResourceName: "oso:2000:zone/example.com",
			resourceName:       "oso:2000:zone/example.com",
			exp:                true,
		},
		{
			name:               "no match on org id",
			policyResourceName: "oso:6666:zone/example.com",
			resourceName:       "oso:2000:zone/example.com",
			exp:                false,
		},
		{
			name:               "wildcard match on org id",
			policyResourceName: "oso:*:zone/example.com",
			resourceName:       "oso:2000:zone/example.com",
			exp:                true,
		},
		{
			name:               "no match on resource id",
			policyResourceName: "oso:2000:zone/foo.net",
			resourceName:       "oso:2000:zone/example.com",
			exp:                false,
		},
		{
			name:               "wildcard match on resource id",
			policyResourceName: "oso:2000:*",
			resourceName:       "oso:2000:zone/example.com",
			exp:                true,
		},
		{
			name:               "wildcard match on resource type",
			policyResourceName: "oso:2000:*/example.com",
			resourceName:       "oso:2000:zone/example.com",
			exp:                true,
		},
		{
			name:               "wildcard match on resource handle",
			policyResourceName: "oso:2000:zone/*",
			resourceName:       "oso:2000:zone/example.com",
			exp:                true,
		},
	}

	for _, tt := range tests {
		got := tt.policyResourceName.ContainsResourceName(tt.resourceName)
		assert.Equal(t, tt.exp, got)
	}
}

func TestPolicyResourceName_GetType(t *testing.T) {
	tests := []struct {
		name               string
		policyResourceName PolicyResourceName
		expType            string
		expErr             error
	}{
		{
			name:               "zone type",
			policyResourceName: "oso:2000:zone/example.com",
			expType:            "zone",
		},
		{
			name:               "user type",
			policyResourceName: "oso:2000:user/bloblaw",
			expType:            "user",
		},
		{
			name:               "bad policyResourceName",
			policyResourceName: "foobar",
			expErr:             errBadResourceName,
		},
		{
			name:               "bad id",
			policyResourceName: "oso:2000:foobar",
			expErr:             errBadResourceID,
		},
	}

	for _, tt := range tests {
		gotType, err := tt.policyResourceName.GetType()
		if err != nil {
			assert.ErrorIs(t, tt.expErr, err)
		}
		assert.Equal(t, tt.expType, gotType)
	}
}

func Test_toDerivedRoleMap(t *testing.T) {
	orgId := 1
	tests := []struct {
		name string
		denormRoles []*datastore.DenormalizedRole
		want map[int]*DerivedRole
	}{
		{
			name: "empty roles",
			denormRoles: []*datastore.DenormalizedRole{},
			want: map[int]*DerivedRole{},
		},
		{
			name: "role with one policy",
			denormRoles: []*datastore.DenormalizedRole{
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "foo",
						Conditions: types.StringArray{},
					},
				},
			},
			want: map[int]*DerivedRole{
				1: {
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policies: []*RolePolicy{
						{
							Effect: "allow",
							Actions: []string{"view"},
							Resource: PolicyResourceName("foo"),
							Conditions: types.StringArray{},
						},
					},
				},
			},
		},
		{
			name: "role with multiple policies",
			denormRoles: []*datastore.DenormalizedRole{
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "foo",
						Conditions: types.StringArray{},
					},
				},
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 2,
						Name: "baz",
						Effect: "allow",
						Actions: types.StringArray{"delete"},
						ResourceName: "foo",
						Conditions: types.StringArray{},
					},
				},
			},
			want: map[int]*DerivedRole{
				1: {
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policies: []*RolePolicy{
						{
							Effect: "allow",
							Actions: []string{"view"},
							Resource: PolicyResourceName("foo"),
							Conditions: types.StringArray{},
						},
						{
							Effect: "allow",
							Actions: []string{"delete"},
							Resource: PolicyResourceName("foo"),
							Conditions: types.StringArray{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toDerivedRoleMap(tt.denormRoles); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toDerivedRoleSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
