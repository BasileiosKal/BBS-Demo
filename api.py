from ursa_bbs_signatures import SignRequest, sign, VerifyRequest, verify, \
    CreateProofRequest, create_proof, \
    VerifyProofRequest, verify_proof
from Canonicalization import JCan
from util import getProofMessages
import base64
import copy

def SignJson(bls_key_pair, credential_json):
    # get messages to sign
    messages_to_sign = JCan(credential_json)

    # create signature
    sign_request = SignRequest(key_pair=bls_key_pair, messages=messages_to_sign)
    signature_raw = sign(sign_request)
    signature_base64_bytes = base64.b64encode(signature_raw)
    signature_base64 = signature_base64_bytes.decode('ascii')


    signed_json = copy.deepcopy(credential_json)
    json_signature_obj = \
    {
        "typ": "BBSSignature2022",
        "signature": signature_base64
    }

    signed_json["proof"] = json_signature_obj
    return signed_json


def VerifyJson(bls_pub_key, signed_credential_json):
    # seperate the credential and the signature obj
    credential_json = copy.deepcopy(signed_credential_json)
    json_signature_obj = credential_json["proof"]
    del credential_json["proof"]
    
    # get the signed messages
    messages_to_verify = JCan(credential_json)

    # get the signature value
    signature_base64 = json_signature_obj["signature"]
    signature_base64_bytes = signature_base64.encode('ascii')
    signature_raw = base64.b64decode(signature_base64_bytes)

    # verify signature
    signature_verify_request = VerifyRequest(key_pair=bls_pub_key, \
        signature=signature_raw, \
        messages=messages_to_verify)

    signature_verify_result = verify(signature_verify_request)

    return signature_verify_result


def ProofGenJson(bls_pub_key, signed_credential_json, revealed_credential_json):
    # seperate the credential and the signature obj
    credential_json = copy.deepcopy(signed_credential_json)
    json_proof_obj = credential_json["proof"]
    del credential_json["proof"]

    # get the signed messages
    signed_messages = JCan(credential_json)

    # get the revealed messages
    revealed_messages = JCan(revealed_credential_json)

    # get the proof messages
    proof_messages = getProofMessages(signed_messages, revealed_messages)

    # get the signature value
    signature_base64 = json_proof_obj["signature"]
    signature_raw = base64.b64decode(signature_base64)

    # get bbs key from bls key (the bls key + the generators)
    claims_no = len(signed_messages)
    bbs_pub_key = bls_pub_key.get_bbs_key(claims_no)

    # create proof
    proof_request = CreateProofRequest(public_key=bbs_pub_key,
                                   messages=proof_messages, 
                                   signature=signature_raw, 
                                   nonce=b'PROOF_NONCE')

    proof_value_raw = create_proof(proof_request)
    proof_value_base64_bytes = base64.b64encode(proof_value_raw)
    proof_value_base64 = proof_value_base64_bytes.decode('ascii')

    credential_with_proof = copy.deepcopy(revealed_credential_json)
    json_proof_value_obj = \
    {
        "typ": "BBSProof2022",
        "cln": claims_no, # cln = claims numper
        "proofValue": proof_value_base64
    }

    credential_with_proof["proof"] = json_proof_value_obj

    return credential_with_proof


def ProofVerifyJson(bls_pub_key, credential_with_proof):
    # seperate the credential and the proof obj
    revealed_credential = copy.deepcopy(credential_with_proof)
    proof_json_obj = revealed_credential["proof"]
    del revealed_credential["proof"]

    # get the revealed messages
    revealed_messages = JCan(revealed_credential)

    # get the bbs public key (the bls key + the generators for each message)
    claims_no = proof_json_obj["cln"]
    bbs_pub_key = bls_pub_key.get_bbs_key(claims_no)

    # get the raw proof value
    proof_value_base64 = proof_json_obj["proofValue"]
    proof_value_raw = base64.b64decode(proof_value_base64)

    # verify the proof
    proof_verify_request = VerifyProofRequest(public_key=bbs_pub_key,
                                          proof=proof_value_raw,
                                          messages=revealed_messages,
                                          nonce=b'PROOF_NONCE')
    
    proof_verify_res = verify_proof(proof_verify_request)

    return proof_verify_res