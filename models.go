package main

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	Allow string = "allow"
	Deny string = "deny"
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
				Resource: ResourceIdentifier{
					Type: "zone", Id: "*",
				},
			},
			{
				Effect: Allow,
				Actions: []string{"delete"},
				Resource: ResourceIdentifier{
					Type: "zone", Id: "1",
				},
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
				Resource: ResourceIdentifier{
					Type: "zone", Id: "*",
				},
			},
			{
				Effect: Deny,
				Actions: []string{"delete"},
				Resource: ResourceIdentifier{
					Type: "zone", Id: "1",
				},
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
	Resource ResourceIdentifier
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

// Zone resource
type Zone struct {
	Id   int
	Name string
	Org int
}

// SuffixMatch returns True if zone name has given suffix
func (z Zone) SuffixMatch(suffix string) bool {
	return strings.HasSuffix(z.Name, suffix)
}

var zonesDb = []Zone{
	{Id: 0, Name: "gmail.com", Org: 0},
	{Id: 1, Name: "react.net", Org: 0},
	{Id: 2, Name: "oso.com", Org: 0},
	{Id: 3, Name: "authz.net", Org: 0},
}

// GetZoneById fetches a zone resource by it's ID
func GetZoneById(id int) (*Zone, error) {
	if len(zonesDb) > id {
		return &zonesDb[id], nil
	}
	return nil, fmt.Errorf("zone with ID %d not found", id)
}
