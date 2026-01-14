local function validate_client_roles(allowed_client_roles, jwt_claims)
    if allowed_client_roles == nil or #allowed_client_roles == 0 then
        return true
    end

    if jwt_claims == nil or jwt_claims.resource_access == nil then
        return nil, "Missing required resource_access claim"
    end

    -- Build a set of allowed client:role pairs for O(1) lookup
    local allowed_set = {}
    for _, allowed_client_role in pairs(allowed_client_roles) do
        allowed_set[allowed_client_role] = true
    end

    -- Check if any claim client:role is in the allowed set
    for claim_client, claim_client_roles in pairs(jwt_claims.resource_access) do
        for _, curr_claim_client_roles in pairs(claim_client_roles) do
            for _, curr_claim_client_role in pairs(curr_claim_client_roles) do
                local client_role_key = claim_client .. ":" .. curr_claim_client_role
                if allowed_set[client_role_key] then
                    return true
                end
            end
        end
    end

    return nil, "Missing required role"
end

local function validate_roles(allowed_roles, jwt_claims)
    if allowed_roles == nil or #allowed_roles == 0 then
        return true
    end

    if jwt_claims.azp == nil then
        return nil, "Missing required azp claim"
    end

    local tmp_allowed = {}
    for i, allowed in pairs(allowed_roles) do
        tmp_allowed[i] = jwt_claims.azp .. ":" .. allowed
    end
    
    return validate_client_roles(tmp_allowed, jwt_claims)
end

local function validate_realm_roles(allowed_realm_roles, jwt_claims)
    if allowed_realm_roles == nil or #allowed_realm_roles == 0 then
        return true
    end

    if jwt_claims == nil or jwt_claims.realm_access == nil or jwt_claims.realm_access.roles == nil then
        return nil, "Missing required realm_access.roles claim"
    end

    -- Build a set of allowed roles for O(1) lookup
    local allowed_set = {}
    for _, role in pairs(allowed_realm_roles) do
        allowed_set[role] = true
    end

    -- Check if any claim role is in the allowed set
    for _, curr_claim_role in pairs(jwt_claims.realm_access.roles) do
        if allowed_set[curr_claim_role] then
            return true
        end
    end

    return nil, "Missing required realm role"
end

return {
    validate_client_roles = validate_client_roles,
    validate_realm_roles = validate_realm_roles,
    validate_roles = validate_roles
}
