package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gobwas/glob"
)

const (
	Allow string = "allow"
	Deny string = "deny"
)

var (
	errBadResourceID = fmt.Errorf("improperly formatted resource ID")
	errBadNRN = fmt.Errorf("improperly formated NRN")
)

// Org relation not yet implemented
type Org struct {
	Id int
	Name string
}

var orgsDb = []Org{
	{Id: 0, Name: "aperture science"},
}

// Role resource
type Role struct {
	Id int
	Name   string
	Policies []Policy

	// These would be FKs
	Org int
}

var rolesDb = []Role{
	{
		Id: 0,
		Name: "viewZonesAndDeleteOne",
		Org: 0,
		Policies: []Policy{
			{
				Effect: Allow,
				Actions: []string{"view"},
				/*Resource: ResourceIdentifier{
					Type: "zone", Id: "*",
				},*/
				Resource: "oso:0:zone/*",
			},
			{
				Effect: Allow,
				Actions: []string{"delete"},
				/*Resource: ResourceIdentifier{
					Type: "zone", Id: "1",
				},*/
				Resource: "oso:0:zone/react.net",
			},
		},
	},
	{
		Id: 1,
		Name: "deleteZonesExceptOne",
		Org: 0,
		Policies: []Policy{
			{
				Effect: Allow,
				Actions: []string{"delete"},
				/*Resource: ResourceIdentifier{
					Type: "zone", Id: "*",
				},*/
				Resource: "oso:0:zone/*",
			},
			{
				Effect: Deny,
				Actions: []string{"delete"},
				/*Resource: ResourceIdentifier{
					Type: "zone", Id: "1",
				},*/
				Resource: "oso:0:zone/react.net",
			},
		},
	},
}

// GetRoleById fetches RBAC role by it's ID
func GetRoleById(id int) (*Role, error) {
	if len(rolesDb) > id {
		return &rolesDb[id], nil
	}
	return nil, fmt.Errorf("role with ID %d not found", id)
}

// User resource
type User struct {
	Id int
	Name string
	ApiKey string
	// These would be FKs
	Roles []int
	Org int
}

// GetRoles returns slice of all role objects assigned to a user
func (u User) GetRoles() []Role {
	var roles []Role
	for _, rId := range u.Roles {
		r, err := GetRoleById(rId)
		if err != nil {
			continue
		}
		roles = append(roles, *r)
	}
	return roles
}

var usersDb = map[string]User{
	"larry": {
		Id: 0,
		Name: "larry",
		Roles: []int{0},
		Org: 0,
		ApiKey: "larry",
	},
	"bob": {
		Id: 0,
		Name: "bob",
		Roles: []int{1},
		Org: 0,
		ApiKey: "bob",
	},
}

// GetCurrentUser returns the User object that corresponds to the provided apiKey
func GetCurrentUser(apiKey string) (*User, error)  {
	for _, u := range usersDb {
		if u.ApiKey == apiKey {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("user with apikey %s not found", apiKey)
}

// Policy resource
type Policy struct {
	Effect string
	Actions []string
	Resource ResourceIdentifierV2
	Conditions []Condition
}

// Condition modifier for policies
type Condition struct {
Type string
Value interface{}
}

// ResourceIdentifier modifier for policies
type ResourceIdentifier struct {
	Type string
	Id string
}

// IdToInt converts ID of ResourceIdentifier to int for comparison to native ID of resource in polar policy
func (r ResourceIdentifier) IdToInt() int {
	id, err := strconv.Atoi(r.Id)
	if err != nil {
		return -1
	}
	return id
}

// ResourceIdentifierV2 is a resource identifier modifier based solely on namespacing
type ResourceIdentifierV2 string

// ContainsNRN checks if resource identifier contains given NRN
func (r ResourceIdentifierV2) ContainsNRN(namespace string) bool {
	orgIDinR, rsrcIDinR, err := SplitNRN(string(r))
	if err != nil {
		return false
	}
	orgIDinN, rsrcIDinN, err := SplitNRN(namespace)
	if err != nil {
		return false
	}
	// match on org id
	if orgIDinR != "*" && orgIDinR != orgIDinN {
		return false
	}
	// match on resource ID
	g, _ := glob.Compile(rsrcIDinR)
	return g.Match(rsrcIDinN)
}

// GetType returns resource type in resource's NRN
func (r ResourceIdentifierV2) GetType() (string, error) {
	rID, err := r.GetResourceID()
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
func (r ResourceIdentifierV2) IsType(t string) bool {
	rType, err := r.GetType()
	if err != nil {
		return false
	}
	return rType == t
}

func (r ResourceIdentifierV2) GetResourceID() (string, error) {
	_, rID, err := SplitNRN(string(r))
	if err != nil {
		return "", err
	}
	return rID, nil
}

func SplitNRN(nrn string) (orgID string, rID string, err error) {
	s := strings.Split(nrn, ":")
	if len(s) != 3 {
		return "", "", errBadNRN
	}
	return s[1], s[2], nil
}

// Zone resource
type Zone struct {
	Id   int
	Name string
	Org int
	Nrn string
}

// SuffixMatch returns True if zone name has given suffix
func (z Zone) SuffixMatch(suffix string) bool {
	return strings.HasSuffix(z.Name, suffix)
}

var zonesDb = []Zone{
	{Id: 0, Name: "gmail.com", Org: 0, Nrn: "oso:0:zone/gmail.com"},
	{Id: 1, Name: "react.net", Org: 0, Nrn: "oso:0:zone/react.net"},
	{Id: 2, Name: "oso.com", Org: 0, Nrn: "oso:0:zone/oso.com"},
	{Id: 3, Name: "authz.net", Org: 0, Nrn: "oso:0:zone/authz.net"},
}

// GetZoneById fetches a zone resource by it's ID
func GetZoneById(id int) (*Zone, error) {
	if len(zonesDb) > id {
		return &zonesDb[id], nil
	}
	return nil, fmt.Errorf("zone with ID %d not found", id)
}

// GetZoneByNrn fetches a zone resource by it's NRN
func GetZoneByNrn(nrn string) (*Zone, error) {
	for _, z := range zonesDb {
		if z.Nrn == nrn {
			return &z, nil
		}
	}
	return nil, fmt.Errorf("zone with NRN %s not found", nrn)
}