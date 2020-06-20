
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.msp import MSP
import json
from hashlib import sha256
import charm.toolbox.symcrypto
import os, struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from colorama import Fore, Style

import hashlib
import treelib
from anytree import Node, RenderTree, util, LevelOrderGroupIter, AsciiStyle, LevelOrderIter
from anytree.exporter import DotExporter

import IDABE


groupObj = PairingGroup('SS512')
cpabe = IDABE.IDABE(groupObj)
gpfile = "global.param"
cpabe.setupGP(gpfile)
attr_dict = cpabe.read_attr_dict("attributes_map.json")
pk_params = "pk.param"

# Example inputs
# access_policy = '((attr1 and attr2) or (attr2 and attr3) or (attr3 and attr4) or (attr5 and attr6))'
# msg = "test message"
# revIDlist_u = ["ru1", "ru2", "ru3"]
# non_revIDlist_a = ['org1', 'org2', 'org3']
# ctxt_filename = "ctxt.json"

def enc_message(msg, access_policy, revIDlist_u, non_revIDlist_a, ctxt_filename):
	symk = groupObj.random(GT)
	rand_key_bytes = objectToBytes(symk, cpabe.group)
	key = sha256(rand_key_bytes).digest()
	cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
	sym_ciphertext = cipher.encrypt(msg)

	for attr, num in attr_dict.items():
		access_policy = access_policy.replace(attr, num)

	revIDlist = []
	for revID in revIDlist_u:
		revIDlist.append(cpabe.group.hash(revID, ZR))
		
	ctxt_store = cpabe.encrypt( pk_params, symk, access_policy, 
		revIDlist, non_revIDlist_a, ctxt_filename)
	return (ctxt_store, sym_ciphertext)


# Example inputs
# "test_user.sk"
def dec_message(ctxt_store, sym_ciphertext, key_user_filename):
	rec_msg = cpabe.decrypt_ctxt_json(ctxt_store, key_user_filename)
	if rec_msg:
		print("decryption successful")
		dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
		deckey = sha256(dec_key_bytes).digest()
		deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
		return deccipher.decrypt(sym_ciphertext).decode('UTF_8')
	return None


def main():
	msg = "test message" # for user identity : test_user, attributes: attr3 and attr4, org_id: 'org3'
	access_policy = '((attr1 and attr2) or (attr2 and attr3) or (attr3 and attr4) or (attr5 and attr6))'
	# access_policy = '((attr1 and attr2) or (attr2 and attr3))' 	# not satisfying access policy
	revIDlist_u = ["ru1", "ru2", "ru3"]
	# revIDlist_u = ["ru1", "ru2", "test_user"] # test_user is revoked
	non_revIDlist_a = ['org1', 'org2', 'org3']
	# non_revIDlist_a = ['org1', 'org2'] # 'org3' is revoked
	ctxt_filename = "ctxt.json"
	
	(ctxt_store, sym_ciphertext) = enc_message(msg, access_policy, revIDlist_u, non_revIDlist_a, ctxt_filename)

	key_user_filename = "org1.sk"
	message = dec_message(ctxt_store, sym_ciphertext, key_user_filename)
	if message:
		print("message is ", message)


if __name__ == "__main__":
	debug = True
	main()



