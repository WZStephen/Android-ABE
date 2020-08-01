import IDABE
from charm.toolbox.pairinggroup import PairingGroup, GT, ZR
from anytree import Node, RenderTree, AsciiStyle
from colorama import Fore, Style
from charm.core.engine.util import objectToBytes, bytesToObject
from hashlib import sha256
import charm.toolbox.symcrypto
import os
from charm.core.math.pairing import ZR
from charm.toolbox.policytree import *
import json
import os, struct
from flask import request
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.IBSig import *


debug = False


def main():
	userID = "test_user"
	key_file_user = "test_user.sk"
	user_assigned_attr = ['attr3', 'attr4']

	groupObj = PairingGroup('SS512')
	cpabe = IDABE.IDABE(groupObj)
	gpfile = "global.param"
	cpabe.setupGP(gpfile)

	user_attr_list = []
	attr_dict = cpabe.read_attr_dict("attributes_map.json")
	for attr in user_assigned_attr:
		user_attr_list.append(attr_dict[attr])

	cpabe.external_delegate("org3.sk", key_file_user, userID, user_attr_list, "pk.param")
	if debug:
		ctxt_filename = "ctxt.json"
		# the example AES key which will be encrypted by ABE scheme
		symk = groupObj.random(GT)
		rand_key_bytes = objectToBytes(symk, cpabe.group)
		key = sha256(rand_key_bytes).digest()
		cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
		# the example message to be encrypted by AES
		msg = "test message"
		ciphertext = cipher.encrypt(msg)
		access_policy = '((attr1 and attr2) or (attr2 and attr3) or (attr3 and attr4) or (attr5 and attr6))'
		for attr, num in attr_dict.items():
			access_policy = access_policy.replace(attr, num)

		# revoked users
		revID1 = cpabe.group.hash("orgx", ZR)
		revID2 = cpabe.group.hash("orgy", ZR)
		revID3 = cpabe.group.hash("orgz", ZR)
		revIDlist_u = [revID1, revID2, revID3]
		# revoked authorities
		non_revIDlist_a = ['org1', 'org2', 'org3']
			
		cpabe.encrypt( "pk.param", symk, access_policy, 
			revIDlist_u, non_revIDlist_a, ctxt_filename)
			
		rec_msg = cpabe.decrypt_file(ctxt_filename, key_file_user)

		if rec_msg:
			assert symk == rec_msg, "FAILED DECRYPTION"
			print("decryption successful")
			dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
			deckey = sha256(dec_key_bytes).digest()
			deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
			print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))



if __name__ == '__main__':
	debug = True
	main()
