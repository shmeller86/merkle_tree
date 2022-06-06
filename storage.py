
import json
import os
import secrets
from coincurve import PublicKey
from pprint import pprint as pp
from sha3 import keccak_256
os.system("clear")

def getPK() -> None:
    return PublicKey.from_valid_secret(keccak_256(secrets.token_bytes(32)).digest()).format(compressed=False)[1:]

def addressGenerate(total: int) -> None:
    address_list = dict()
    address_list = {
        "addresses": list("0x" + keccak_256(getPK()).digest()[-20:].hex() for x in range(0,total)),
        "hashes": []
    } 
    with open("./address_list.json", "w") as fp:
        json.dump(address_list, fp,indent=4)
    print(f"\nADDRESS LIST:\n" + "\n".join(address_list['addresses']))

def getAddressList() -> None:
    with open("./address_list.json", "r", encoding='utf-8') as fp:
        return json.load(fp)

def keccak256(hc: list) -> str:
    hs = keccak_256()
    hs.update("".join(hc).encode('utf-8'))
    return hs.hexdigest()

def merkleTreeEncode(al: list) -> list:
    al = al['addresses']
    hash_candidate, hash_tree, loop = list(), list(), 0

    while(True):
        if loop == len(hash_tree):
            hash_tree.append(list())
        hash_candidate.append(al.pop())
        if (len(hash_candidate) == 1 and loop == 0) or (len(hash_candidate) == 2 and loop > 0):
            hash_tree[loop].append(keccak256(hash_candidate))
            hash_candidate = list()
        elif len(hash_candidate) == 1 and len(al) == 0 and loop > 0:
            hash_candidate.append(hash_candidate[0])
            hash_tree[loop].append(keccak256(hash_candidate))
        if len(al) == 0:
            if len(hash_tree[loop]) > 1:
                al = list(hash_tree[loop])
                hash_candidate = list()
                loop += 1
            else:
                break
    
    data = json.load(open("address_list.json", "r"))
    data['hashes'] = hash_tree
    json.dump(data, open("address_list.json", "w"), indent=4)
    return hash_tree

def merkleTreeDependens(address: str)-> dict:
    address_list = getAddressList()
    try:
        index = address_list['addresses'].index(address)
    except Exception as e:
        print('invalid address')
        return []

    data = {}
    data['index'] = index
    data['hash'] = address_list['hashes'][0][index]
    data['root'] = address_list['hashes'][len(address_list['hashes'])-1]

    out = []
    first = True
    total = len(address_list['hashes'][0])

    for level in address_list['hashes']:
        if len(level) == 1:
            break
        if len(level) % 2 != 0:
            level.append(level[len(level)-1])
        if first:
            if (index+1) % 2 == 0:    
                out.append(level[index-1])
            else:
                out.append(level[index+1])
            first = False
        else:
            if (index+1) % 2 == 0:    
                out.append(level[index-1])
            else:
                out.append(level[index+1])
        index = int((index) / 2)
        total = total/2
    data['proof'] = out
    return data



len_address = 15
try:
    adress_list = getAddressList()
    hashes = merkleTreeEncode(adress_list)
except Exception as e:
    print(e)
    addressGenerate(len_address)
    adress_list = getAddressList()
    hashes = merkleTreeEncode(adress_list)

hash_root = hashes[len(hashes)-1][0]
print(f"root hash: {hash_root} \n")


dep = merkleTreeDependens("0x7499797cc04091372f3bc16c2a51f5ade6777952")
pp(dep)