import json
import ursa_bbs_signatures

# Canonicalize the credential
def _getClaims(JsonCredential, claims_list, claim):

    if isinstance(JsonCredential, dict):
        to_iter = JsonCredential
        prfx = ""
    elif isinstance(JsonCredential, list):
        to_iter = range(len(JsonCredential))
        prfx = "#id"

    for key in to_iter:
        claim.append(prfx + str(key))
        value = JsonCredential[key]

        if isinstance(value, dict):
            _getClaims(value, claims_list, claim)
        elif isinstance(value, list):
            _getClaims(value, claims_list, claim)
        else:
            claim_res = '.'.join(claim)
            claim_res += ": " + str(value)
            claims_list.append(claim_res)

        claim.pop()
    return claims_list

def JCan(Credential):
    claims = _getClaims(Credential, [], [])
    return claims
