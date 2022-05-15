# BBS+ Demo with JSON

Install the dependencies with,
```
python -m pip requirements.txt
```

From the root directory, run the demo with,
```
python demo.py
```
Keep hitting ("Enter") until the demo ends

### API

Example of the abstracted api, meant to handle json credentials.

```
# Key Generation
key_pair = BlsKeyPair.generate_g2()
pub_key = BlsKeyPair(public_key=bls_key_pair.public_key)

# The original credential
credential = {"name": "Joe", 
              "age": 20}

# The frame indicating the parts of the credential to be revealed
frame = {"name": ""} # will only reveal the name

# Sign the credential
signed_credential = SignJson(key_pair, credential)

# Verify the signed credential
sig_verification_res = VerifyJson(pub_key, signed_credential)

# frame the credential
revealed_credential = getRevealedCredential(credential, frame)

# create the proof
revealed_json_with_proof = ProofGenJson(pub_key, signed_credential, revealed_credential)

# verify the proof 
proof_verification_res = ProofVerifyJson(pub_key, revealed_json_with_proof)
```