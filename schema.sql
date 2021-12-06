create table org
(
	org_id serial not null
		constraint org_pkey
			primary key,
	name varchar(50) not null
);

create table condition (
    condition_id serial PRIMARY KEY NOT NULL,
    type text NOT NULL,
    value text NOT NULL
);

create table policy
(
    policy_id serial PRIMARY KEY NOT NULL,
    name text NOT NULL,
    effect text NOT NULL,
    actions text[],
    resource_name text NOT NULL
);

create table condition_policies (
    condition_id INT references condition(condition_id),
    policy_id INT references policy(policy_id),
    PRIMARY KEY(condition_id, policy_id)
);

create table role (
    role_id serial PRIMARY KEY NOT NULL,
    name text NOT NULL,
    org_id INT REFERENCES org(org_id) NOT NULL
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
    org_id INT references org(org_id) NOT NULL
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
INSERT INTO zone (name, resource_name, org_id) VALUES ('authz.net', 'oso:0:zone/authz.net', 1);

/* conditions */
INSERT INTO condition (type, value) VALUES ('matchSuffix', 'com');

/* policies */
INSERT INTO policy (name, effect, actions, resource_name) VALUES ('viewZones', 'allow', '{"view"}', 'oso:0:zone/*');
INSERT INTO policy (name, effect, actions, resource_name) VALUES ('deleteOneZone', 'allow', '{"delete"}', 'oso:0:zone/react.net');
INSERT INTO policy (name, effect, actions, resource_name) VALUES ('viewOneZone', 'allow', '{"view"}', 'oso:0:zone/gmail.com');
INSERT INTO policy (name, effect, actions, resource_name) VALUES ('deleteZones', 'allow', '{"delete"}', 'oso:0:zone/*');
INSERT INTO policy (name, effect, actions, resource_name) VALUES ('viewComZones', 'allow', '{"view"}', 'oso:0:zone/*');

/* join conditions to policies */
INSERT INTO condition_policies (condition_id, policy_id) VALUES (1, 5);

/* roles */
INSERT INTO role (name, org_id) VALUES ('viewZonesAndDeleteOne', 1);
INSERT INTO role (name, org_id) VALUES ('deleteZonesAndViewOne', 1);
INSERT INTO role (name, org_id) VALUES ('viewComZones', 1);

/* join policies to roles */
INSERT INTO role_policies (role_id, policy_id) VALUES (1, 1);
INSERT INTO role_policies (role_id, policy_id) VALUES (1, 2);
INSERT INTO role_policies (role_id, policy_id) VALUES (2, 3);
INSERT INTO role_policies (role_id, policy_id) VALUES (2, 4);
INSERT INTO role_policies (role_id, policy_id) VALUES (3, 5);

/* users */
/* bob can view all zones and delete react.net */
INSERT INTO "user" (name, api_key, org_id) VALUES ('bob', 'bob', 1);
/* tom can delete all zones and view gmail.com */
INSERT INTO "user" (name, api_key, org_id) VALUES ('tom', 'tom', 1);
/* joe can view zones with com suffix */
INSERT INTO "user" (name, api_key, org_id) VALUES ('joe', 'joe', 1);


/* join users to roles */
INSERT INTO user_roles (user_id, role_id) VALUES (1, 1);
INSERT INTO user_roles (user_id, role_id) VALUES (2, 2);
INSERT INTO user_roles (user_id, role_id) VALUES (3, 3);
