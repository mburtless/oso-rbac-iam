package datastore

import (
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/mburtless/oso-rbac-iam/pkg/roles"
	"github.com/stretchr/testify/assert"
	"github.com/volatiletech/sqlboiler/v4/types"
	"reflect"
	"testing"
)

func Test_ToEffectivePerms(t *testing.T) {
	orgId := 1
	tests := []struct {
		name string
		denormRoles []*DenormalizedRole
		want EffectivePerms
	}{
		{
			name: "empty roles",
			denormRoles: []*DenormalizedRole{},
			want: EffectivePerms{},
		},
		{
			name: "role with one policy",
			denormRoles: []*DenormalizedRole{
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "oso:0:zone/foo",
					},
				},
			},
			want: EffectivePerms{
				Namespaces: map[string][]string{
					//"zone": {"oso:0:zone/foo"},
				},
				AllowPolicies: PoliciesByNamespace{
					"oso:0:zone/foo": map[int]*roles.RolePolicy{
						1: {
							ID: 1,
							Effect:     "allow",
							Actions:    []string{"view"},
							Resource:   roles.PolicyResourceName("oso:0:zone/foo"),
							Conditions: map[int]*roles.Condition{},
						},
					},
				},
				DenyPolicies: PoliciesByNamespace{},
			},
		},
		{
			name: "role with policy and one condition",
			denormRoles: []*DenormalizedRole{
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "oso:0:zone/foo",
					},
					Condition: models.Condition{
						ConditionID: 1,
						Type: "matchSuffix",
						Value: "com",
					},
				},
			},
			want: EffectivePerms{
				Namespaces: map[string][]string{
					//"zone": {"oso:0:zone/foo"},
				},
				AllowPolicies: PoliciesByNamespace{
					"oso:0:zone/foo": map[int]*roles.RolePolicy{
						1: {
							ID: 1,
							Effect:     "allow",
							Actions:    []string{"view"},
							Resource:   roles.PolicyResourceName("oso:0:zone/foo"),
							Conditions: map[int]*roles.Condition{
								1: {
									Type: "matchSuffix",
									Value: "com",
								},
							},
						},
					},
				},
				DenyPolicies: PoliciesByNamespace{},
			},
		},
		{
			name: "role with policy and many conditions",
			denormRoles: []*DenormalizedRole{
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "oso:0:zone/foo",
					},
					Condition: models.Condition{
						ConditionID: 1,
						Type: "matchSuffix",
						Value: "com",
					},
				},
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "oso:0:zone/foo",
					},
					Condition: models.Condition{
						ConditionID: 2,
						Type: "matchPrefix",
						Value: "foo",
					},
				},
			},
			want: EffectivePerms{
				Namespaces: map[string][]string{
					//"zone": {"oso:0:zone/foo"},
				},
				AllowPolicies: PoliciesByNamespace{
					"oso:0:zone/foo": map[int]*roles.RolePolicy{
						1: {
							ID: 1,
							Effect:     "allow",
							Actions:    []string{"view"},
							Resource:   roles.PolicyResourceName("oso:0:zone/foo"),
							Conditions: map[int]*roles.Condition{
								1: {
									Type: "matchSuffix",
									Value: "com",
								},
								2: {
									Type: "matchPrefix",
									Value: "foo",
								},
							},
						},
					},
				},
				DenyPolicies: PoliciesByNamespace{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToEffectivePerms(tt.denormRoles); !assert.Equal(t, tt.want, got) {
				t.Errorf("ToEffectivePerms() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ToDerivedRoleMap(t *testing.T) {
	orgId := 1
	tests := []struct {
		name string
		denormRoles []*DenormalizedRole
		want DerivedRoles
	}{
		{
			name: "empty roles",
			denormRoles: []*DenormalizedRole{},
			want: map[int]*DerivedRole{},
		},
		{
			name: "role with one policy",
			denormRoles: []*DenormalizedRole{
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "foo",
					},
				},
			},
			want: map[int]*DerivedRole{
				1: {
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policies: map[int]*roles.RolePolicy{
						1: {
							ID: 1,
							Effect:     "allow",
							Actions:    []string{"view"},
							Resource:   roles.PolicyResourceName("foo"),
							Conditions: map[int]*roles.Condition{},
						},
					},
				},
			},
		},
		{
			name: "role with multiple policies",
			denormRoles: []*DenormalizedRole{
				{
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policy: models.Policy{
						PolicyID: 1,
						Name: "bar",
						Effect: "allow",
						Actions: types.StringArray{"view"},
						ResourceName: "foo",
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
					},
				},
			},
			want: map[int]*DerivedRole{
				1: {
					Role: models.Role{RoleID: 1, Name: "guybrush", OrgID: orgId},
					Policies: map[int]*roles.RolePolicy{
						1: {
							ID: 1,
							Effect:     "allow",
							Actions:    []string{"view"},
							Resource:   roles.PolicyResourceName("foo"),
							Conditions: map[int]*roles.Condition{},
						},
						2: {
							ID: 2,
							Effect:     "allow",
							Actions:    []string{"delete"},
							Resource:   roles.PolicyResourceName("foo"),
							Conditions: map[int]*roles.Condition{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToDerivedRoleMap(tt.denormRoles); !reflect.DeepEqual(got, tt.want) {
				t.Logf("got: %v", got[1].Policies[1])
				t.Errorf("ToDerivedRoleMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

