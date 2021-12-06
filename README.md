# oso-rbac-iam
PoC of an authorization model that utilizes roles with IAM like policies using [Oso](https://www.osohq.com/).

## Getting Started

1. Start Postgres and seed database: `make start`

2. Run server: `go run .`

3. Curl localhost with `x-api-key` header set to user you wish to test with:  `curl -H "x-api-key: tom" http://localhost:5000/zone/1`

### Users for Testing
* `bob` can `GET` all zones and `DELETE` zone `2` (`react.net`)
* `tom` can `DELETE` all zones and `GET` zone `1` (`gmail.com`)
* `joe` can `GET` all zones with suffix `com`

### Zones for Testing
* ID: `1`, Name: `gmail.com` NRN: `oso:0:zone/gmail.com`
* ID: `2`, Name: `react.net` NRN: `oso:0:zone/react.net`
* ID: `3`, Name: `oso.com` NRN: `oso:0:zone/oso.com`
* ID: `4`, Name: `authz.net`, NRN: `oso:0:zone/authz.net`

### Roles for Testing
* `viewZonesAndDeleteOne` contains the following policies:
    * ```
      name: viewZones
      effect: allow
      actions: ["view"]
      resource_name: oso:0:zone/*
      ```
    * ```
      name: deleteOneZone
      effect: allow
      actions: ["delete"]
      resource_name: oso:0:zone/react.net
      ```

* `deleteZonesAndViewOne` contains the following policies:
  * ```
      name: viewOneZone
      effect: allow
      actions: ["view"]
      resource_name: oso:0:zone/gmail.com
      ```
  * ```
      name: deleteZones
      effect: allow
      actions: ["delete"]
      resource_name: oso:0:zone/*
      ```

* `viewComZones` contains the following policies:
  * ```
      name: viewComZones
      effect: allow
      actions: ["view"]
      resource_name: oso:0:zone/*
      conditions: [ {type: "matchSuffix", value: "com"} ]
      ```
