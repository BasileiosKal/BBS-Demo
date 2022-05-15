from ursa_bbs_signatures import BlsKeyPair, BlsKeyPair
from api import SignJson, VerifyJson, ProofGenJson, ProofVerifyJson
from util import getRevealedCredential
import json

# Gen key pair
bls_key_pair = BlsKeyPair.generate_g2()
bls_pub_key = BlsKeyPair(public_key=bls_key_pair.public_key)

# open json and canonicalize them
with open("./data/credential.json") as credential:
    credential_json = json.load(credential)

with  open("./data/frame.json") as frame:
    credential_frame = json.load(frame)
    # revealed_credential_json = json.load(frame)


#####################################  Digital Signature #####################################

input(" ****************************** Digital Signature ******************************* \n")
print("JSON Credential = \n", json.dumps(credential_json, indent=3))

# Signature generation
print("----------------------------------------------------------------------------------")
input("")
input(">>>>> Sign(Key_Pair, Credential)... \n")
credential_with_signature = SignJson(bls_key_pair, credential_json)
print("JSON Credential With Signature = \n", json.dumps(credential_with_signature, indent=3))

# Signature verification
print("----------------------------------------------------------------------------------")
input("")
input(">>>>> Verify(PK, Signed_Credential)... \n")
verify_json_result = VerifyJson(bls_pub_key, credential_with_signature)
print("Signature Verification Result = ", verify_json_result)
print("----------------------------------------------------------------------------------")



################################## ZK selective disclosure ###################################

input("")
input(" ************************** ZK Selective Disclosure *************************** \n")

# Get revealed credential
print("Frame = \n", json.dumps(credential_frame, indent=3))

print("----------------------------------------------------------------------------------")
input("")
input(">>>>> Credential Framing... \n")
revealed_credential_json = getRevealedCredential(credential_json, credential_frame)
print("JSON Revealed Credential = \n", json.dumps(revealed_credential_json, indent=3))

print("----------------------------------------------------------------------------------")
input("")
input(">>>>> ProofGen(PK, Signed_Credential, Revealed_Credential)... \n")
credential_with_proof = ProofGenJson(bls_pub_key, \
    credential_with_signature, revealed_credential_json)
print("JSON Revealed Credential With Proof = \n", json.dumps(credential_with_proof, indent=3))

# Proof Verify
print("----------------------------------------------------------------------------------")
input("")
input(">>>>> ProofVerify(PK, Revealed_Credential_With_Proof)... \n")
proof_verify_json_result = ProofVerifyJson(bls_pub_key, credential_with_proof)
print("Proof Verification Result = ", proof_verify_json_result)
print("----------------------------------------------------------------------------------")
