import IDABE
from charm.toolbox.pairinggroup import PairingGroup, GT, ZR
from anytree import Node, RenderTree, AsciiStyle
from colorama import Fore, Style
from charm.core.engine.util import objectToBytes, bytesToObject
from hashlib import sha256
import charm.toolbox.symcrypto
import os

debug = False

def main():
	groupObj = PairingGroup('SS512')
	cpabe = IDABE.IDABE(groupObj)
	gpfile = "global.param"
	cpabe.setupGP(gpfile)

	ta_conf = cpabe.read_attr_dict("TAs.config")
	print("TA configurations: ", ta_conf)
	TAset = ta_conf['TAs']
	ta_msk_filenames = ta_conf['TAmsk']
	ta_pk_filenames = ta_conf['TApubs']

	ta_sk_filenames = {"ta1": "ta1.org.sk", "ta2": "ta2.org.sk", "ta3": "ta3.org.sk"}
	root_org = "org1"

	attr_assigned_str = ['attr1', 'attr2', 'attr3', 'attr4', 'attr5', 'attr6', 'attr7', 'attr8', 'attr9', 'attr10']
	attr_assigned = []
	attr_dict = cpabe.read_attr_dict("attributes_map.json")
	for attr in attr_assigned_str:
		attr_assigned.append(attr_dict[attr])

	for i in range(1, len(TAset) + 1):
		ta_name = "ta" + str(i)
		cpabe.org_keygen(attr_assigned, root_org, ta_msk_filenames[ta_name], ta_pk_filenames[ta_name], 
		ta_sk_filenames[ta_name], "pk.param", root_org)

	for i in range(1, len(TAset)):
		ta_first = "ta" + str(i)
		ta_second = "ta" + str(i+1)
		cpabe.federated_org_keygen(root_org, attr_assigned, ta_msk_filenames[ta_second], "pk.param", ta_sk_filenames[ta_first], ta_sk_filenames[ta_second], root_org)
	
	command = "cp {} {}".format(ta_sk_filenames[TAset[-1]], root_org+".sk")
	print("command is ", command)
	os.system(command)

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
			
		rec_msg = cpabe.decrypt_file(ctxt_filename, ta_sk_filenames['ta3'])
		print(rec_msg)
		if rec_msg:
			assert symk == rec_msg, "FAILED DECRYPTION"
			print("decryption successful")
			dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
			deckey = sha256(dec_key_bytes).digest()
			deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
			print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))

if __name__ == "__main__":
	debug = False
	main()
