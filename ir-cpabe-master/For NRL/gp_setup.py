import IDABE
from charm.toolbox.pairinggroup import PairingGroup

def main():
	groupObj = PairingGroup('SS512')
	cpabe = IDABE.IDABE(groupObj)
	gpfile = "global.param"
	attr_dict = cpabe.read_attr_dict("attributes_map.json")
	attr_size = len(attr_dict)
	cpabe.gsetup(attr_size, gpfile) #glonal.param
	print( "Copy {} to all the servers and clients which use the ABE scheme".format(gpfile))
	print(gpfile + " is the file containing global parameters such as math group used \n")

if __name__ == "__main__":
    main()



