from ursa_bbs_signatures import ProofMessage, ProofMessageType
from Canonicalization import JCan
import json

def getProofMessages(messages, revealed_messages):
    if not (set(revealed_messages) <= set(messages)):
        raise ValueError("Revealed messages is not subset of the initial messages")
    
    # get messages for the proof
    proof_messages = []
    for msg in messages:
        if msg in revealed_messages:
            proof_messages.append(ProofMessage(msg, ProofMessageType(1)))
        else:
            proof_messages.append(ProofMessage(msg, ProofMessageType(2)))
    
    return proof_messages


def _frameCredential(credential, frame, result = {}):

    if isinstance(credential, dict):
        to_iter = credential
    elif isinstance(credential, list):
        to_iter = range(len(credential))
    else: to_iter = credential

    for key in to_iter:
        if str(key) in frame:
            if isinstance(credential[key], dict):

                if isinstance(result, list):  result.append({})
                elif isinstance(result, dict): result[key] = {}
                else: raise ValueError("Invalid key or value")

                _frameCredential(credential[key], frame[str(key)], result[key])
            elif isinstance(credential[key], list):
    
                if isinstance(result, list):  result.append([])
                elif isinstance(result, dict): result[key] = []
                else: raise ValueError("Invalid key or value")
    
                _frameCredential(credential[key], frame[str(key)], result[key])
            else: 
                result[key] = credential[key]

    return result


def getRevealedCredential(json_credential, frame):
    res = _frameCredential(json_credential, frame)
    return res


if __name__ == "__main__":
    with open("./data/credential.json") as credential:
        credential_json = json.load(credential)

    with  open("./data/frame.json") as frame:
        frame_json = json.load(frame)
    
    res = getRevealedCredential(credential_json, frame_json)
    print(" --> FINAL RESULT = ", res)
