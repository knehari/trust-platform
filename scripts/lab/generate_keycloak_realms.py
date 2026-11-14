#!/usr/bin/env python3
"""Lab only. Generates the Keycloak realm imports in scripts/lab/keycloak/
(ADR-0009). The files hold no secrets: passwords and the workload secret are
${...} placeholders that Keycloak fills from the environment (.env.lab).
Usage: python3 -I scripts/lab/generate_keycloak_realms.py scripts/lab/keycloak
"""
import json, sys
CONSOLE = "http://127.0.0.1:5173"
TRUST_ROLES = {
    "trust-ca-reader": "Read the CAs, certificates, audit events and profile drafts granted to the user.",
    "trust-profile-editor": "Record and submit certificate-profile draft revisions (with a profile-editor grant for the CA).",
    "trust-policy-approver": "Approve or reject an exact submitted profile revision with a registered key (with a policy-approver grant for the CA).",
    "trust-ca-operator": "Activate or retire an approved profile revision (with a ca-operator grant for the CA).",
    "trust-ca-administrator": "Propose a CA, register its self-signed issuer certificate and activate it once approved (with a ca-administrator platform grant).",
    "trust-ca-approver": "Approve or reject a key-attested CA proposal, or a CA reactivation or retirement, with a registered key (with a ca-approver platform grant).",
    "trust-certificate-requester": "Submit certificate applications for a CA's active profiles (with a certificate-requester grant for the CA).",
    "trust-registration-officer": "Approve or reject certificate applications of others (with a registration-officer grant for the CA).",
}
def uid(n): return f"7c1a0000-0000-4000-8000-{n:012d}"
# The laboratory issuing CA (ADR-0016): proposed with this identifier through
# the API so that token CA scopes can name it before it exists.
LAB_ISSUING_CA = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
def mappers(access_only=True):
    common = {"access.token.claim": "true", "id.token.claim": "false",
              "userinfo.token.claim": "false", "introspection.token.claim": "true"}
    return [
        {"name": "trust-api audience", "protocol": "openid-connect",
         "protocolMapper": "oidc-audience-mapper",
         "config": {"included.custom.audience": "trust-api", **common}},
        {"name": "trust roles", "protocol": "openid-connect",
         "protocolMapper": "oidc-usermodel-realm-role-mapper",
         "config": {"claim.name": "roles", "multivalued": "true", "jsonType.label": "String", **common}},
        {"name": "trust CA scope", "protocol": "openid-connect",
         "protocolMapper": "oidc-usermodel-attribute-mapper",
         "config": {"user.attribute": "ca_ids", "claim.name": "ca_ids", "multivalued": "true",
                    "jsonType.label": "String", **common}},
    ]
def console_client():
    return {
        "clientId": "trust-console", "name": "Trust Platform laboratory console",
        "enabled": True, "publicClient": True, "protocol": "openid-connect",
        "standardFlowEnabled": True, "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
        "frontchannelLogout": False, "consentRequired": False,
        "redirectUris": [f"{CONSOLE}/auth/callback"], "webOrigins": [CONSOLE],
        "attributes": {"pkce.code.challenge.method": "S256",
                       "post.logout.redirect.uris": f"{CONSOLE}##{CONSOLE}/",
                       "access.token.header.type.rfc9068": "true"},
        "fullScopeAllowed": False,
        "defaultClientScopes": ["basic", "profile", "acr"], "optionalClientScopes": [],
        "protocolMappers": mappers(),
    }
def user(n, name, pw_env, roles, cas, enabled=True):
    return {"id": uid(n), "username": name, "enabled": enabled,
            "firstName": name, "lastName": "Laboratory", "email": f"{name}@lab.invalid", "emailVerified": True,
            "attributes": {"ca_ids": cas},
            "credentials": [{"type": "password", "value": "${%s}" % pw_env, "temporary": False}],
            "realmRoles": roles}
def realm(name, display, users, clients, scope_roles):
    return {
        "realm": name, "displayName": display, "enabled": True,
        "sslRequired": "external", "registrationAllowed": False, "resetPasswordAllowed": False,
        "rememberMe": False, "verifyEmail": False, "loginWithEmailAllowed": False,
        "duplicateEmailsAllowed": False, "editUsernameAllowed": False,
        "bruteForceProtected": True, "permanentLockout": False, "failureFactor": 5,
        "waitIncrementSeconds": 60, "maxFailureWaitSeconds": 900, "quickLoginCheckMilliSeconds": 1000,
        "minimumQuickLoginWaitSeconds": 60, "maxDeltaTimeSeconds": 43200,
        "passwordPolicy": "length(16) and notUsername and notEmail",
        "accessTokenLifespan": 300, "ssoSessionIdleTimeout": 900, "ssoSessionMaxLifespan": 3600,
        "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        "defaultSignatureAlgorithm": "RS256",
        "roles": {"realm": [{"name": f"default-roles-{name}", "composite": False,
                             "description": "Default role: grants nothing, not even the account console."}]
                           + [{"name": r, "description": d} for r, d in TRUST_ROLES.items()]},
        "defaultRole": {"name": f"default-roles-{name}"},
        "clients": clients,
        "scopeMappings": [{"client": c["clientId"], "roles": scope_roles} for c in clients],
        "users": users,
    }
lab_users = [
    user(1, "lab-reader", "TRUST_LAB_PW_READER", ["trust-ca-reader"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]),
    user(2, "lab-editor", "TRUST_LAB_PW_EDITOR", ["trust-profile-editor"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]),
    user(3, "lab-approver-1", "TRUST_LAB_PW_APPROVER_1", ["trust-ca-reader", "trust-policy-approver"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", LAB_ISSUING_CA]),
    user(4, "lab-approver-2", "TRUST_LAB_PW_APPROVER_2", ["trust-ca-reader", "trust-policy-approver"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", LAB_ISSUING_CA]),
    user(5, "lab-operator", "TRUST_LAB_PW_OPERATOR", ["trust-ca-reader", "trust-ca-operator"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", LAB_ISSUING_CA]),
    user(6, "lab-outsider", "TRUST_LAB_PW_OUTSIDER", [], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]),
    user(7, "lab-disabled", "TRUST_LAB_PW_DISABLED", ["trust-ca-reader"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"], enabled=False),
    user(8, "lab-other-ca", "TRUST_LAB_PW_OTHER_CA", ["trust-ca-reader"], ["ffffffff-ffff-4fff-8fff-ffffffffffff"]),
    user(11, "lab-author", "TRUST_LAB_PW_AUTHOR", ["trust-ca-reader", "trust-profile-editor"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", LAB_ISSUING_CA]),
    user(12, "lab-ca-admin", "TRUST_LAB_PW_CA_ADMIN", ["trust-ca-administrator"], []),
    user(13, "lab-ca-approver-1", "TRUST_LAB_PW_CA_APPROVER_1", ["trust-ca-approver"], []),
    user(14, "lab-ca-approver-2", "TRUST_LAB_PW_CA_APPROVER_2", ["trust-ca-approver"], []),
    user(15, "lab-requester", "TRUST_LAB_PW_REQUESTER", ["trust-ca-reader", "trust-certificate-requester"], [LAB_ISSUING_CA]),
    user(16, "lab-ra-officer", "TRUST_LAB_PW_RA_OFFICER", ["trust-ca-reader", "trust-registration-officer"], [LAB_ISSUING_CA]),
    # A second officer for dual-control steps: revocation decisions and the
    # confirmation of a void (ADR-0018, ADR-0020).
    user(17, "lab-ra-officer-2", "TRUST_LAB_PW_RA_OFFICER_2", ["trust-ca-reader", "trust-registration-officer"], [LAB_ISSUING_CA]),
    {"id": uid(9), "username": "service-account-trust-lab-workload", "enabled": True,
     "serviceAccountClientId": "trust-lab-workload",
     "attributes": {"ca_ids": ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]},
     "realmRoles": ["trust-ca-reader"]},
]
workload = {
    "clientId": "trust-lab-workload", "name": "Laboratory workload (client credentials)",
    "enabled": True, "publicClient": False, "protocol": "openid-connect",
    "clientAuthenticatorType": "client-secret", "secret": "${TRUST_LAB_WORKLOAD_SECRET}",
    "standardFlowEnabled": False, "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
    "attributes": {"access.token.header.type.rfc9068": "true"},
    "fullScopeAllowed": False, "defaultClientScopes": ["basic"], "optionalClientScopes": [],
    "protocolMappers": mappers(),
}
roles = list(TRUST_ROLES)
out = sys.argv[1]
json.dump(realm("trust-lab", "Trust Platform laboratory", lab_users, [console_client(), workload], roles),
          open(f"{out}/trust-lab-realm.json", "w"), indent=2)
open(f"{out}/trust-lab-realm.json", "a").write("\n")
foreign_users = [user(10, "foreign-reader", "TRUST_LAB_PW_FOREIGN", ["trust-ca-reader"], ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"])]
json.dump(realm("trust-lab-foreign", "Foreign laboratory issuer (must be refused)", foreign_users, [console_client()], roles),
          open(f"{out}/trust-lab-foreign-realm.json", "w"), indent=2)
open(f"{out}/trust-lab-foreign-realm.json", "a").write("\n")
