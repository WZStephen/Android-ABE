import IDABE
from charm.toolbox.pairinggroup import PairingGroup
from anytree import Node, RenderTree, AsciiStyle
from colorama import Fore, Style
import os

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

	# org tree structure
	root_org = "org1"
	root = Node("org1")
	org2 = Node("org2", parent = root)
	org3 = Node("org3", parent = root)
	org4 = Node("org4", parent = root)
	org5 = Node("org5", parent = org2)
	org6 = Node("org6", parent = org2)
	print("Organization Tree Structure\n")
	print(Fore.BLUE + RenderTree(root, style=AsciiStyle()).by_attr())
	print(Style.RESET_ALL)

	# each TA first generate theri own public key and msk key
	for ta in TAset:
		cpabe.ta_setup_tree(ta_pk_filenames[ta], ta_msk_filenames[ta], root)

	# this simulates how multiple TAs generate the fe
	for i in range(1, len(TAset)):
		ta_first = "ta" + str(i)
		ta_second = "ta" + str(i+1)
		cpabe.federated_setup1(ta_pk_filenames[ta_first], ta_pk_filenames[ta_second], 
			ta_msk_filenames[ta_second], root)
	
	command = "cp {} {}".format(ta_pk_filenames[TAset[-1]], "pk.param")
	print("command is ", command)
	os.system(command)


if __name__ == "__main__":
    main()