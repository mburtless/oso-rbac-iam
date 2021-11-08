package main

import (
	"fmt"
	"github.com/gobwas/glob"
	"github.com/mburtless/oso-rbac-iam/datastore"
	"github.com/mburtless/oso-rbac-iam/models"
	"github.com/volatiletech/sqlboiler/v4/types"
	"strings"
)

var (
	errBadResourceID   = fmt.Errorf("improperly formatted resource ID")
	errBadResourceName = fmt.Errorf("improperly formated resource name")
)
// converts a slice of denormalized roles into a map of derived roles
func toDerivedRoleMap(denormRoles []*datastore.DenormalizedRole) map[int]*DerivedRole {
	derivedRoles := map[int]*DerivedRole{}
	if len(denormRoles) == 0 {
		return derivedRoles
	}
	for _, denormRole := range denormRoles {
		// check if derived role already exists at index
		if _, ok := derivedRoles[denormRole.Role.RoleID]; !ok {
			// if not, populate it with current role
			derivedRoles[denormRole.Role.RoleID] = &DerivedRole{
				Role: denormRole.Role,
				Policies: []*RolePolicy{},
			}
		}
		// append policy
		derivedRoles[denormRole.Role.RoleID].Policies = append(derivedRoles[denormRole.Role.RoleID].Policies, toPolicy(&denormRole.Policy))
	}
	return derivedRoles
}

// DerivedRole is the combination of a role and all of it's policies
type DerivedRole struct {
	models.Role
	Policies []*RolePolicy
}

// RolePolicy resource
type RolePolicy struct {
	Effect     string
	Actions    []string
	Resource   PolicyResourceName
	Conditions types.StringArray
}

func toPolicy(policy *models.Policy) *RolePolicy {
	return &RolePolicy{
		Effect: policy.Effect,
		Actions: policy.Actions,
		Resource: PolicyResourceName(policy.ResourceName),
		Conditions: policy.Conditions,
	}
}

// Condition modifier for policies
type Condition struct {
	Type  string
	Value interface{}
}
// PolicyResourceName is a resource name modifier for use in Policies
type PolicyResourceName string

// ContainsResourceName checks if policy resource name contains given resource name
func (prn PolicyResourceName) ContainsResourceName(rn string) bool {
	orgIDinPRN, rIDinPRN, err := SplitResourceName(string(prn))
	if err != nil {
		return false
	}
	orgIDinRN, rIDinRN, err := SplitResourceName(rn)
	if err != nil {
		return false
	}
	// match on org id
	if orgIDinPRN != "*" && orgIDinPRN != orgIDinRN {
		return false
	}
	// match on resource ID
	g, _ := glob.Compile(rIDinPRN)
	return g.Match(rIDinRN)
}

// GetType returns resource type in resource's NRN
func (prn PolicyResourceName) GetType() (string, error) {
	rID, err := prn.GetResourceID()
	if err != nil {
		return "", err
	}
	t := strings.Split(rID, "/")
	if len(t) < 2 {
		return "", errBadResourceID
	}
	return t[0], nil
}

// IsType returns true if resource is given type t
func (prn PolicyResourceName) IsType(t string) bool {
	rType, err := prn.GetType()
	if err != nil {
		return false
	}
	return rType == t
}

func (prn PolicyResourceName) GetResourceID() (string, error) {
	_, rID, err := SplitResourceName(string(prn))
	if err != nil {
		return "", err
	}
	return rID, nil
}

// SplitResourceName splits a resource name into org ID and resource ID
func SplitResourceName(nrn string) (orgID string, rID string, err error) {
	s := strings.Split(nrn, ":")
	if len(s) != 3 {
		return "", "", errBadResourceName
	}
	return s[1], s[2], nil
}
