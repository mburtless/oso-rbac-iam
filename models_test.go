package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResourceIdentifierV2_InNamespace(t *testing.T) {
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
