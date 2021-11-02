create table org
(
	org_id serial not null
		constraint org_pkey
			primary key,
	name varchar(50) not null
);

create type policy_condition AS (
    type text,
    value text
);

create table policy
(
    policy_id serial PRIMARY KEY NOT NULL,
    name text NOT NULL,
    effect text NOT NULL,
    actions text[],
    resource_name text,
    conditions policy_condition[]
);

create table role (
    role_id serial PRIMARY KEY NOT NULL,
    name text NOT NULL,
    org_id INT REFERENCES org(org_id)
);

create table role_policies (
    role_id INT references role(role_id),
    policy_id INT references policy(policy_id),
    PRIMARY KEY(role_id, policy_id)
);

create table "user" (
    user_id serial PRIMARY KEY NOT NULL,
    name text NOT NULL,
    api_key text NOT NULL,
    org_id INT references org(org_id)
);

create table user_roles (
    user_id INT references "user"(user_id),
    role_id INT references role(role_id),
    PRIMARY KEY(user_id, role_id)
);

create table zone (
    zone_id serial PRIMARY KEY NOT NULL,
    name text NOT NULL,
    resource_name text NOT NULL,
    org_id INT REFERENCES org(org_id) NOT NULL
);

/* TEST DATA */
/* org */
INSERT INTO org (name) VALUES ('Aperture Science');

/* zones */
INSERT INTO zone (name, resource_name, org_id) VALUES ('gmail.com', 'oso:0:zone/gmail.com', 1);
INSERT INTO zone (name, resource_name, org_id) VALUES ('react.net', 'oso:0:zone/react.net', 1);
INSERT INTO zone (name, resource_name, org_id) VALUES ('oso.com', 'oso:0:zone/oso.com', 1);
INSERT INTO zone (name, resource_name, org_id) VALUES ('authz.com', 'oso:0:zone/authz.net', 1);

/* policies */
INSERT INTO policy (name, effect, actions, resource_name) VALUES ('viewZones', 'allow', '{"view"}', 'oso:0:zone/*');

/* roles */
INSERT INTO role (name, org_id) VALUES ('viewZones', 1);

/* join policies to roles */
INSERT INTO role_policies (role_id, policy_id) VALUES (1, 1);

/* users */
INSERT INTO "user" (name, api_key, org_id) VALUES ('bob', 'bob', 1);

/* join users to roles */
INSERT INTO user_roles (user_id, role_id) VALUES (1, 1);