package roles

import (
	"fmt"
	"github.com/gobwas/glob"
	"strings"
)

var (
	errBadResourceID   = fmt.Errorf("improperly formatted resource ID")
	errBadResourceName = fmt.Errorf("improperly formated resource name")
)



// RolePolicy resource
type RolePolicy struct {
	ID int
	Effect     string
	Actions    []string
	Resource   PolicyResourceName
	Conditions map[int]*Condition
}

func (rp RolePolicy) String() string {
	return fmt.Sprintf("ID: %d Effect: %s Actions: %v Resource: %v Conditions: %v",
		rp.ID, rp.Effect, rp.Actions, rp.Resource, rp.Conditions,
	)
}

// Condition modifier for policies
type Condition struct {
	Type  string
	Value interface{}
	ID int
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
