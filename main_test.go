package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

func Test_setup(t *testing.T) {
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
			apiKey:  "larry",
			expErr:  false,
			expCode: 200,
			expBody: "<h1>A Repo</h1><p>Welcome larry to zone gmail.com</p>",
		},
		{
			name:    "view nonexistant zone",
			route:   "/zone/5",
			method:  "GET",
			apiKey:  "larry",
			expErr:  false,
			expCode: 404,
			expBody: "<h1>Whoops!<h1><p>zone with ID 5 not found</p>",
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
			route:   "/zone/3",
			method:  "DELETE",
			apiKey:  "bob",
			expErr:  false,
			expCode: 200,
			expBody: "<h1>A Repo</h1><p>Welcome bob to zone authz.net</p>",
		},
		{
			name:   "delete zone without authz",
			route:  "/zone/1",
			method: "DELETE",
			apiKey: "bob",
			expErr: false,
			// TODO: change to 401
			expCode: 404,
			expBody: "<h1>Whoops!</h1><p>That zone was not found</p>",
		},
	}
	if err := initOso(); err != nil {
		log.Fatalf("Failed to initialize Oso: %s", err.Error())
	}
	app := setup()

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
