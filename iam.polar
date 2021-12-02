actor DerivedUser {}

# allowed if there is a role with a policy that allows action
# and no role with a policy that explicitly denies action
allow(user: DerivedUser, action: String, resource) if
    some_allow(user, action, resource) and
    no_deny(user, action, resource);

some_allow(user: DerivedUser, action: String, resource) if
    # policy exists in allowpolicies for resource
    [key, policies] in user.Permissions.AllowPolicies and
    key_contains_resource_name(key, resource) and
    # policy allows action
    policy in policies and
    check_policy(policy, action, resource);

key_contains_resource_name(key, _resource: Zone) if
    key = "oso:0:zone/*";

key_contains_resource_name(key, resource: Zone) if
    key = resource.ResourceName;

no_deny(user: DerivedUser, action: String, resource) if
    forall([key, policies] in user.Permissions.DenyPolicies,
        not key_contains_resource_name(key, resource) or
        (policy in policies and
        not check_policy(policy, action, resource))
    );

# policy is a match if it permits the action on the resource and meets specified condition
check_policy(policy: RolePolicy, action: String, _resource) if
    policy_permits_action(policy, action);
    # TODO: fix conditionals
    #conditions_hold(policy, resource);

# either policy allows all actions
policy_permits_action(policy, _action) if
    "*" in policy.Actions;

# or policy allows specific action
policy_permits_action(policy, action) if
    action in policy.Actions;

# all conditions in policy must pass
conditions_hold(policy, resource) if
    forall(
        condition in policy.Conditions,
        check_conditions(condition, resource)
    );

# matchAttributes type policy
check_conditions(condition, resource) if
    condition.Type = "matchAttributes" and
    forall([k, v] in condition.Value,
        resource.(k) = v
    );

# matchSuffix type policy
check_conditions(condition, resource) if
    condition.Type = "matchSuffix" and
    resource.SuffixMatch(condition.Value);
