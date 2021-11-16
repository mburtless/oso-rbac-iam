actor DerivedUser {}

# allowed if there is a role with a policy that allows action
# and no role with a policy that explicitly denies action
allow(user: DerivedUser, action: String, resource) if
    some_allow(user, action, resource) and
    no_deny(user, action, resource);

some_allow(user: DerivedUser, action: String, resource) if
    [_, role] in user.Roles and
    # TODO: switch policies to map
    [_, policy] in role.Policies and
    policy.Effect = "allow" and
    check_policy(policy, action, resource);

no_deny(user: DerivedUser, action: String, resource) if
    [_, role] in user.Roles and
    forall([_, policy] in role.Policies,
        not policy.Effect = "deny" or
        not check_policy(policy, action, resource)
    );

# policy is a match if it permits the action on the resource and meets specified condition
check_policy(policy: RolePolicy, action: String, resource) if
    policy_permits_action(policy, action) and
    resource_matches(policy, resource);
    # TODO: fix conditionals
    #conditions_hold(policy, resource);

# either policy allows all actions
policy_permits_action(policy, _action) if
    "*" in policy.Actions;

# or policy allows specific action
policy_permits_action(policy, action) if
    action in policy.Actions;

# either policy allows all zone resources
resource_matches(policy, _resource: Zone) if
    policy.Resource.IsType("zone") = true and
    policy.Resource.GetResourceID() = "*";

# or nrn in policy allows specific zone
resource_matches(policy, resource: Zone) if
    policy.Resource.IsType("zone") = true and
    policy.Resource.ContainsResourceName(resource.ResourceName);

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
