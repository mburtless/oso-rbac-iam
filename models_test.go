package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResourceIdentifierV2_InNamespace(t *testing.T) {
	tests := []struct {
		name string
		policyNRN ResourceIdentifierV2
		resourceNRN string
		exp bool
	}{
		{
			name: "exact match",
			policyNRN: "oso:2000:zone/example.com",
			resourceNRN: "oso:2000:zone/example.com",
			exp: true,
		},
		{
			name: "no match on org id",
			policyNRN: "oso:6666:zone/example.com",
			resourceNRN: "oso:2000:zone/example.com",
			exp: false,
		},
		{
			name: "wildcard match on org id",
			policyNRN: "oso:*:zone/example.com",
			resourceNRN: "oso:2000:zone/example.com",
			exp: true,
		},
		{
			name: "no match on resource id",
			policyNRN: "oso:2000:zone/foo.net",
			resourceNRN: "oso:2000:zone/example.com",
			exp: false,
		},
		{
			name: "wildcard match on resource id",
			policyNRN: "oso:2000:*",
			resourceNRN: "oso:2000:zone/example.com",
			exp: true,
		},
		{
			name: "wildcard match on resource type",
			policyNRN: "oso:2000:*/example.com",
			resourceNRN: "oso:2000:zone/example.com",
			exp: true,
		},
		{
			name: "wildcard match on resource handle",
			policyNRN: "oso:2000:zone/*",
			resourceNRN: "oso:2000:zone/example.com",
			exp: true,
		},
	}

	for _, tt := range tests {
		got := tt.policyNRN.ContainsNRN(tt.resourceNRN)
		assert.Equal(t, tt.exp, got)
	}
}

func TestResourceIdentifierV2_GetType(t *testing.T) {
	tests := []struct {
		name string
		nrn ResourceIdentifierV2
		expType string
		expErr error
	}{
		{
			name: "zone type",
			nrn: "oso:2000:zone/example.com",
			expType: "zone",
		},
		{
			name: "user type",
			nrn: "oso:2000:user/bloblaw",
			expType: "user",
		},
		{
			name: "bad nrn",
			nrn: "foobar",
			expErr: errBadNRN,
		},
		{
			name: "bad id",
			nrn: "oso:2000:foobar",
			expErr: errBadResourceID,
		},
	}

	for _, tt := range tests {
		gotType, err := tt.nrn.GetType()
		if err != nil {
			assert.ErrorIs(t, tt.expErr, err)
		}
		assert.Equal(t, tt.expType, gotType)
	}
}