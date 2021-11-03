# oso-rbac-iam
PoC of an authorization model that utilizes roles with IAM like policies using [Oso](https://www.osohq.com/).

## Getting Started

1. Start Postgres and seed database: `make start`

2. Run server: `go run .`

3. Curl localhost with `x-api-key` header set to user you wish to test with:  `curl -H "x-api-key: tom" http://localhost:5000/zone/1`
