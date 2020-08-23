'''
Qiuxiang Dong

| From: "Achieving Fine-Grained Access Control with Discretionary User Revocation over Cloud Data"
| Published in: 2018
| Available from: https://ieeexplore.ieee.org/abstract/document/8433128/
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing

:Authors:         Qiuxiang Dong; Dijiang Huang ; Jim Luo ; Myong Kang
:Date:            09/2019
'''

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
from charm.toolbox.secretutil import SecretUtil #newly added by Weichi

import hashlib
import treelib
from anytree import Node, RenderTree, util, LevelOrderGroupIter, AsciiStyle, LevelOrderIter
from anytree.exporter import DotExporter

debug = False
test = False
message_enc = False
file_enc = False

class IDABE(ABEnc):

    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.util = (self.group, verbose)
        self.util1 = SecretUtil(self.group, verbose) #newly added by Weichi
        self.util2 = MSP(self.group, verbose) #newly added by Weichi

        # self.g1_bytes = b'eJxNkE0KAjEMha9SZt1F02majFcRKaPMbnajgoh3N3+Cixbykrz3te9pjNu+HscY0ylN19d9O6acRH2u+2Mz9dyWnJBzAgC5ypwTU069+2E5KI1FNCw5teg39tq21GJhb6AuL3F6DJBM4qxF1UsqAvft7KtQqovWZVtsoVRpsWwTegRROGkGt5iAIjKLQqoUubD/8XUL+QWoFVQlY+dgZcGwVLcaGM2w0R9mOEqK1b9E0RHdppFb0Bz5GgulBJp9rZFSjzzFgsvnC/cZUTM='
        # self.g1 = bytesToObject(self.g1_bytes, self.group)
        # self.g2_bytes = b'eJw1kMEOAiEMRH+FcOZAkULxV4whq9mbt1UTY/x3OxQOLGV4Hab79b3fH9tx9O7Pzt8+z/3wwan63h6vfagXjsGxBEdRi6ZLcnCl6X4KrupeCi5VJFKl1eDywPGhZBxX4yrOpGdd0oymSLOXUjKUGTJ4vWptCTCCARYepTpVROIy47QpFplIW1hFU1LLDIaGBVkgOFReOZA9I0e0bvPUQqI9D7RGA0Z+FBgIPpTiwsdkMxQM8S9kTSpsIXlQMtPY3GUNgWa6/v5Dj1H3'
        # self.g2 = bytesToObject(self.g2_bytes, self.group)


    '''
    This function will return set up global parameters of the cpabe class
    '''
    def setupGP(self, filename):
        with open(filename, 'r') as f:
            datastore1 = json.load(f)        
        self.gp = {'g1': bytesToObject(datastore1['g1'].encode('UTF-8'), self.group), 
                'g2': bytesToObject(datastore1['g2'].encode('UTF-8'), self.group),
                'h': bytesToObject(datastore1['h'].encode('UTF-8'), self.group)}
        return self.gp

    '''
    The function gsetup which sets up the whole system's non-secret parameters, including the geneartor 
    of G1, G2, and also the group elements for all the attributes. 

    attrNum: the number of attributes used in the system
    filename: the file to store the generated global parameters, this file should be copied to all the
    entities who use the cpabe module, including TA, orgs and users

    CAUTION: This function will be run only once at the very begining of setting up the whole system
    If run one more time, all the setup should be done again, including TA setup, key generation for
    the root of the organizations, all its subordinated organizations, and users
    '''
    def gsetup(self, attrNum, filename):
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        # g1_bytes = b'eJxNkE0KAjEMha9SZt1F02majFcRKaPMbnajgoh3N3+Cixbykrz3te9pjNu+HscY0ylN19d9O6acRH2u+2Mz9dyWnJBzAgC5ypwTU069+2E5KI1FNCw5teg39tq21GJhb6AuL3F6DJBM4qxF1UsqAvft7KtQqovWZVtsoVRpsWwTegRROGkGt5iAIjKLQqoUubD/8XUL+QWoFVQlY+dgZcGwVLcaGM2w0R9mOEqK1b9E0RHdppFb0Bz5GgulBJp9rZFSjzzFgsvnC/cZUTM='
        # g1 = bytesToObject(self.g1_bytes, self.group)
        # g2_bytes = b'eJw1kMEOAiEMRH+FcOZAkULxV4whq9mbt1UTY/x3OxQOLGV4Hab79b3fH9tx9O7Pzt8+z/3wwan63h6vfagXjsGxBEdRi6ZLcnCl6X4KrupeCi5VJFKl1eDywPGhZBxX4yrOpGdd0oymSLOXUjKUGTJ4vWptCTCCARYepTpVROIy47QpFplIW1hFU1LLDIaGBVkgOFReOZA9I0e0bvPUQqI9D7RGA0Z+FBgIPpTiwsdkMxQM8S9kTSpsIXlQMtPY3GUNgWa6/v5Dj1H3'
        # g2 = bytesToObject(self.g2_bytes, self.group)
        h = [0]
        for i in range(0, attrNum):
            h.append(self.group.random(G1))
            #h.append(g1)
        gp = {'g1': objectToBytes(g1, self.group).decode('UTF-8'),
              'g2': objectToBytes(g2, self.group).decode('UTF-8'),
              'h': objectToBytes(h, self.group).decode('UTF-8') }
        gp_json = json.dumps(gp)
        datastore = json.loads(gp_json)
        with open(filename, 'w') as f:
            json.dump(datastore, f)

    def store_ta_pk(self, pk, filename):
        pk_bytes = {
            'g1': objectToBytes(pk['g1'], self.group).decode('UTF-8'), 
            'g2': objectToBytes(pk['g2'], self.group).decode('UTF-8'), 
            'g2b': objectToBytes(pk['g2b'], self.group).decode('UTF-8'),
            'g1b': objectToBytes(pk['g1b'], self.group).decode('UTF-8'), 
            'g1bb': objectToBytes(pk['g1bb'], self.group).decode('UTF-8'), 
            'e_gg_alpha': objectToBytes(pk['e_gg_alpha'], self.group).decode('UTF-8'), 
            'h': objectToBytes(pk['h'], self.group).decode('UTF-8'), 
            'hb': objectToBytes(pk['hb'], self.group).decode('UTF-8'),
            'hbb': objectToBytes(pk['hbb'], self.group).decode('UTF-8'), 
            'gsIDs': objectToBytes(pk['gsIDs'], self.group).decode('UTF-8'),
            'gbsIDs': objectToBytes(pk['gbsIDs'], self.group).decode('UTF-8'),
            'sID': objectToBytes(pk['sID'], self.group).decode('UTF-8'),
            'sIDr': objectToBytes(pk['sIDr'], self.group).decode('UTF-8')
        }
            
        pk_json = json.dumps(pk_bytes)
        datastore = json.loads(pk_json)
        with open(filename, 'w') as f:
            json.dump(datastore, f)

    def read_ta_pk(self, filename):
        with open(filename, 'r') as f:
            datastore = json.load(f)
        
        pk = {
            'g1': bytesToObject(datastore['g1'].encode('UTF-8'), self.group), 
            'g2': bytesToObject(datastore['g2'].encode('UTF-8'), self.group), 
            'g1b': bytesToObject(datastore['g1b'].encode('UTF-8'), self.group), 
            'g2b': bytesToObject(datastore['g2b'].encode('UTF-8'), self.group), 
            'g1bb': bytesToObject(datastore['g1bb'].encode('UTF-8'), self.group), 
            'e_gg_alpha': bytesToObject(datastore['e_gg_alpha'].encode('UTF-8'), self.group), 
            'h': bytesToObject(datastore['h'].encode('UTF-8'), self.group), 
            'hb': bytesToObject(datastore['hb'].encode('UTF-8'), self.group),
            'hbb': bytesToObject(datastore['hbb'].encode('UTF-8'), self.group), 
            'gsIDs': bytesToObject(datastore['gsIDs'].encode('UTF-8'), self.group),
            'gbsIDs': bytesToObject(datastore['gbsIDs'].encode('UTF-8'), self.group),
            'sID': bytesToObject(datastore['sID'].encode('UTF-8'), self.group),
            'sIDr': bytesToObject(datastore['sIDr'].encode('UTF-8'), self.group)
        }

        return pk

    def save_global_public_params(self, global_public_param_file, ta_pk_filename):
        pk = self.read_ta_pk(ta_pk_filename)
        pp_bytes = {
            'g1': objectToBytes(pk['g1'], self.group).decode('UTF-8'), 
            'g2': objectToBytes(pk['g2'], self.group).decode('UTF-8'), 
            'g2b': objectToBytes(pk['g2b'], self.group).decode('UTF-8'),
            'g1b': objectToBytes(pk['g1b'], self.group).decode('UTF-8'), 
            'g1bb': objectToBytes(pk['g1bb'], self.group).decode('UTF-8'), 
            'e_gg_alpha': objectToBytes(pk['e_gg_alpha'], self.group).decode('UTF-8'), 
            'h': objectToBytes(pk['h'], self.group).decode('UTF-8'), 
            'hb': objectToBytes(pk['hb'], self.group).decode('UTF-8'),
            'hbb': objectToBytes(pk['hbb'], self.group).decode('UTF-8'), 
            'gsIDs': objectToBytes(pk['gsIDs'], self.group).decode('UTF-8'),
            'gbsIDs': objectToBytes(pk['gbsIDs'], self.group).decode('UTF-8')
        }
            
        pp_json = json.dumps(pp_bytes)
        datastore = json.loads(pp_json)
        with open(global_public_param_file, 'w') as f:
            json.dump(datastore, f)
    
    def read_global_public_params(self, filename):
        with open(filename, 'r') as f:
            datastore = json.load(f)
        
        pp = {
            'g1': bytesToObject(datastore['g1'].encode('UTF-8'), self.group), 
            'g2': bytesToObject(datastore['g2'].encode('UTF-8'), self.group), 
            'g1b': bytesToObject(datastore['g1b'].encode('UTF-8'), self.group), 
            'g2b': bytesToObject(datastore['g2b'].encode('UTF-8'), self.group), 
            'g1bb': bytesToObject(datastore['g1bb'].encode('UTF-8'), self.group), 
            'e_gg_alpha': bytesToObject(datastore['e_gg_alpha'].encode('UTF-8'), self.group), 
            'h': bytesToObject(datastore['h'].encode('UTF-8'), self.group), 
            'hb': bytesToObject(datastore['hb'].encode('UTF-8'), self.group),
            'hbb': bytesToObject(datastore['hbb'].encode('UTF-8'), self.group), 
            'gsIDs': bytesToObject(datastore['gsIDs'].encode('UTF-8'), self.group),
            'gbsIDs': bytesToObject(datastore['gbsIDs'].encode('UTF-8'), self.group)
        }

        return pp

    def store_ta_msk(self, msk, filename):
        msk_bytes = {
            'alpha': objectToBytes(msk['alpha'], self.group).decode('UTF-8'), 
            'b': objectToBytes(msk['b'], self.group).decode('UTF-8'),
            's': objectToBytes(msk['s'], self.group).decode('UTF-8')
            }
        msk_json = json.dumps(msk_bytes)
        datastore = json.loads(msk_json)
        with open(filename, 'w') as f:
            json.dump(datastore, f)

    def read_ta_msk(self, filename):
        with open(filename, 'r') as f:
            datastore1 = json.load(f)
        
        msk = {
            'alpha': bytesToObject(datastore1['alpha'].encode('UTF-8'), self.group), 
            'b': bytesToObject(datastore1['b'].encode('UTF-8'), self.group),
            's': bytesToObject(datastore1['s'].encode('UTF-8'), self.group)
            }
        return msk

    '''
    Single Key Generation
    '''
    def store_org_key(self, filename, key):
        key_bytes = {
            'attr_list': key['attr_list'],
            'K0': objectToBytes( key['K0'], self.group ).decode('UTF-8'),
            'Lu': objectToBytes(key['Lu'], self.group).decode('UTF-8'), 
            'La': objectToBytes(key['La'], self.group).decode('UTF-8'), 
            'Ka': key['Ka'],
            'Ku': key['Ku'],
            'hx': key['hx'],
            'hxt': key['hxt'],
            'hxbt': key['hxbt'],
            'ID': key['ID'],
            'sID': objectToBytes(key['sID'], self.group).decode('UTF-8'),
            'gbsID': objectToBytes(key['gbsID'], self.group).decode('UTF-8'),
            'gbt': objectToBytes(key['gbt'], self.group).decode('UTF-8'),
            'org_id': key['org_id']
        }

        key_json = json.dumps(key_bytes)
        datastore = json.loads(key_json)
        with open(filename, 'w') as f:
            json.dump(datastore, f)

    def store_user_key(self, filename, key):
        key_bytes = {
            'attr_list': key['attr_list'],
            'K0': objectToBytes( key['K0'], self.group ).decode('UTF-8'),
            'Lu': objectToBytes(key['Lu'], self.group).decode('UTF-8'), 
            'La': objectToBytes(key['La'], self.group).decode('UTF-8'), 
            'Ka': key['Ka'],
            'Ku': key['Ku'],
            'ID': key['ID'],
            'org_id': key['org_id']
        }

        key_json = json.dumps(key_bytes)
        datastore = json.loads(key_json)
        with open(filename, 'w') as f:
            json.dump(datastore, f)

    def read_org_key(self, filename):
        with open(filename, 'r') as f:
            datastore = json.load(f) 
        
        Ka_objects = {}
        for key, value in datastore['Ka'].items():
            Ka_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)

        Ku_objects = {}
        for key, value in datastore['Ku'].items():
            Ku_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)
                
        hx_objects = {}
        for key, value in datastore['hx'].items():
            hx_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)

        hxt_objects = {}
        for key, value in datastore['hxt'].items():
            hxt_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)
                 
        hxbt_objects = {}
        for key, value in datastore['hxbt'].items():
            hxbt_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)

        key = {
            'attr_list': datastore['attr_list'],
            # 'ID': bytesToObject( datastore['ID'].encode('UTF-8'), self.group),
            'ID': datastore['ID'],
            'K0': bytesToObject( datastore['K0'].encode('UTF-8'), self.group),
            'Lu': bytesToObject(datastore['Lu'].encode('UTF-8'), self.group),
            'La': bytesToObject(datastore['La'].encode('UTF-8'), self.group), 
            'sID': bytesToObject(datastore['sID'].encode('UTF-8'), self.group), 
            'gbsID': bytesToObject(datastore['gbsID'].encode('UTF-8'), self.group), 
            'gbt': bytesToObject(datastore['gbt'].encode('UTF-8'), self.group), 
            'Ka': Ka_objects,
            'Ku': Ku_objects,
            'hx': hx_objects,
            'hxt': hxt_objects,
            'hxbt': hxbt_objects,
            'org_id': datastore['org_id']
        }

        return key

    def read_user_key(self, filename):
        with open(filename, 'r') as f:
            datastore = json.load(f) 
        
        Ka_objects = {}
        for key, value in datastore['Ka'].items():
            Ka_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)

        Ku_objects = {}
        for key, value in datastore['Ku'].items():
            Ku_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)
                
        key = {
            'attr_list': datastore['attr_list'],
            'ID': datastore['ID'],
            'K0': bytesToObject( datastore['K0'].encode('UTF-8'), self.group),
            'Lu': bytesToObject(datastore['Lu'].encode('UTF-8'), self.group),
            'La': bytesToObject(datastore['La'].encode('UTF-8'), self.group), 
            'Ka': Ka_objects,
            'Ku': Ku_objects,
            'org_id': datastore['org_id']
        }

        return key

    def store_ctxt(self, filename, ctxt):
        datastore = self.set_ctxt(ctxt)
        with open(filename, 'w') as f:
            json.dump(datastore, f)  

    def set_ctxt(self, ctxt):
        ctxt_bytes = {
        'policy': ctxt['policy'],
        'c0': objectToBytes(ctxt['c0'], self.group).decode('UTF-8'), 
        'c_m': objectToBytes(ctxt['c_m'], self.group).decode('UTF-8'), 
        'C_u_star': ctxt['C_u_star'],
        'C_u_prime': ctxt['C_u_prime'],
        'revIDlist_u': ctxt['revIDlist_u'],
        'C_a_prime': ctxt['C_a_prime'],
        'C_a_star': ctxt['C_a_star'],
        'non_revIDlist_a': ctxt['non_revIDlist_a']
        }
            
        ctxt_json = json.dumps(ctxt_bytes)
        datastore = json.loads(ctxt_json)
        return datastore

    def read_ctxt(self, filename):
        with open(filename, 'r') as f:
            datastore1 = json.load(f)
        return self.get_ctxt(datastore1)

    def get_ctxt(self, datastore1):              
        Clistobjects={}
        i = 0
        num = len(datastore1['revIDlist_u'])
        Clistobjects={}
        while i < num:
          Clistobjects[i] = {}
          for key, value in datastore1['C_u_star'][str(i)].items():
              Clistobjects[i][key] = bytesToObject(value.encode('UTF-8'), self.group)
          i = i+1
        
        Dlistobjects={}
        i = 0
        while i < num:
          Dlistobjects[i] = {}
          for key, value in datastore1['C_u_prime'][str(i)].items():
              Dlistobjects[i][key] =  bytesToObject(value.encode('UTF-8'), self.group)
          i = i+1
        
        revIDlist_u = datastore1['revIDlist_u']
        revIDobjects = []
        for revID in revIDlist_u:
          revIDobjects.append(bytesToObject(revID.encode('UTF-8'), self.group))
        
        non_revIDlist_a = datastore1['non_revIDlist_a']

        Castar_objects = {}
        i = 0
        while i < len(non_revIDlist_a):
          Castar_objects[non_revIDlist_a[i]] = {}
          for key, value in datastore1['C_a_star'][non_revIDlist_a[i]].items():
              Castar_objects[non_revIDlist_a[i]][key] =  bytesToObject(value.encode('UTF-8'), self.group)
          i = i+1
        
        Caprime_objects = {}
        for key, value in datastore1['C_a_prime'].items():
            Caprime_objects[key] = bytesToObject(value.encode('UTF-8'), self.group)       
        
        ctxt = {'policy': datastore1['policy'], 
              'c0': bytesToObject(datastore1['c0'].encode('UTF-8'), self.group), 
              'c_m': bytesToObject(datastore1['c_m'].encode('UTF-8'), self.group), 
              'revIDlist_u':revIDobjects,
              'non_revIDlist_a': non_revIDlist_a,
              'C_u_star': Clistobjects,
              'C_u_prime': Dlistobjects,
              'C_a_star': Castar_objects,
              'C_a_prime': Caprime_objects
        }
    
        return ctxt   

    '''
    root denotes the ROOT node of the tree representing the organization structure
    this method implements how TAi+1 calculates public parameters when received 
    pk from TAi, i >= 1 and i+1 < |TAset|
    '''
    def federated_setup(self, ta_pk_file1, ta_pk_file2, ta_msk_file2, ta_msk_file1, root):
        all_orgs = [node for node in LevelOrderIter(root)]
        pk1 = self.read_ta_pk(ta_pk_file1)

        msk2 = self.read_ta_msk(ta_msk_file2)
        msk1 = self.read_ta_msk(ta_msk_file1)
        b = msk2['b']
        alpha = msk2['alpha']
        s = msk2['s']
        s = 1

        g2b = pk1['g2b'] ** b
        g1b = pk1['g1b'] ** b
        g1bb = pk1['g1bb'] ** (b*b)
        e_gg_alpha = pk1['e_gg_alpha'] * ( pair(pk1['g1'], pk1['g2']) ** alpha)

        hb = [0]
        hbb = [0]
        for i in range(1, len(pk1['h'])):
            hb.append(pk1['hb'][i] ** b)
            hbb.append(pk1['hbb'][i] ** (b*b))

        sID = {}
        sIDr = {}
        sID[root.name] = pk1['sID'][root.name] * (self.group.hash(root.name, ZR) ** s)
        sIDr[root.name] = 1 / sID[root.name]

        for i in range(1, len(all_orgs)):
            sID[all_orgs[i].name] = self.group.hash(all_orgs[i].name, ZR) ** sID[all_orgs[i].parent.name]
            sIDr[all_orgs[i].name] = 1 / sID[all_orgs[i].name]

        gsIDs = {}
        gbsIDs = {}
        
        for i in range(0, len(all_orgs)):
            gsIDs[all_orgs[i].name] = pk1['g2'] ** sIDr[all_orgs[i].name]
            gbsIDs[all_orgs[i].name] = g2b ** (sIDr[all_orgs[i].name])
        
        pk = {'g1': pk1['g1'],
              'g2': pk1['g2'],
              'g2b': g2b,
              'g1b': g1b,
              'g1bb': g1bb,
              'e_gg_alpha': e_gg_alpha,
              'h': pk1['h'],
              'hb': hb,
              'hbb': hbb,
              'gsIDs': gsIDs,
              'gbsIDs': gbsIDs,
              'sID': sID,
              'sIDr': sIDr
        }

        msk = {
            'b': b * msk1['b'],
            'alpha': alpha + msk1['alpha'],
            's': msk1['s'] + s
        }

        self.store_ta_pk(pk, ta_pk_file2)
        if debug:
            pkread = self.read_ta_pk(ta_pk_file2)
            assert pk == pkread, "FAILED pk store"
        self.store_ta_msk(msk, ta_msk_file2)
        if debug:
            mskread = self.read_ta_msk(ta_msk_file2)
            assert msk == mskread, "FAILED msk store"
        return (pk, msk)

    '''
    root denotes the ROOT node of the tree representing the organization structure
    this method implements how TAi+1 calculates public parameters when received 
    pk from TAi, i >= 1 and i+1 < |TAset|
    '''
    def federated_setup1(self, ta_pk_file1, ta_pk_file2, ta_msk_file2, root):
        all_orgs = [node for node in LevelOrderIter(root)]
        pk1 = self.read_ta_pk(ta_pk_file1)
        msk2 = self.read_ta_msk(ta_msk_file2)
        b = msk2['b']
        alpha = msk2['alpha']
        s = msk2['s']
        s = 1

        g2b = pk1['g2b'] ** b
        g1b = pk1['g1b'] ** b
        g1bb = pk1['g1bb'] ** (b*b)
        e_gg_alpha = pk1['e_gg_alpha'] * (pair(pk1['g1'], pk1['g2']) ** alpha)

        hb = [0]
        hbb = [0]
        for i in range(1, len(pk1['h'])):
            hb.append(pk1['hb'][i] ** b)
            hbb.append(pk1['hbb'][i] ** (b*b))

        sID = {}
        sIDr = {}
        sID[root.name] = pk1['sID'][root.name] * (self.group.hash(root.name, ZR) ** s)
        sIDr[root.name] = 1 / sID[root.name]

        for i in range(1, len(all_orgs)):
            sID[all_orgs[i].name] = self.group.hash(all_orgs[i].name, ZR) ** sID[all_orgs[i].parent.name]
            sIDr[all_orgs[i].name] = 1 / sID[all_orgs[i].name]

        gsIDs = {}
        gbsIDs = {}
        
        for i in range(0, len(all_orgs)):
            gsIDs[all_orgs[i].name] = pk1['g2'] ** sIDr[all_orgs[i].name]
            gbsIDs[all_orgs[i].name] = g2b ** (sIDr[all_orgs[i].name])
        
        pk = {'g1': pk1['g1'],
              'g2': pk1['g2'],
              'g2b': g2b,
              'g1b': g1b,
              'g1bb': g1bb,
              'e_gg_alpha': e_gg_alpha,
              'h': pk1['h'],
              'hb': hb,
              'hbb': hbb,
              'gsIDs': gsIDs,
              'gbsIDs': gbsIDs,
              'sID': sID,
              'sIDr': sIDr
        }


        self.store_ta_pk(pk, ta_pk_file2)
        if debug:
            pkread = self.read_ta_pk(ta_pk_file2)
            assert pk == pkread, "FAILED pk store"
        return (pk)

    '''
    single setup of trusted authority, should be multiple, it will
    generate pk and msk for each ta which could be used to generate 
    private key in a federated way
    '''
    def ta_setup(self, pk_filename, msk_file, orgIDlist):
        b = self.group.random(ZR)
        alpha = self.group.random(ZR)
        s = self.group.random(ZR)
        sIDr = []
        
        for i in range(0, len(orgIDlist)):
            ID = self.group.hash(orgIDlist[i], ZR)
            sID = (ID ** s)
            sIDr.append(1/sID)

        g1 = self.gp['g1']
        g1b = g1 ** b
        g1bb = g1b ** b
        g2 = self.gp['g2']
        g2b = g2 ** b
        h = self.gp['h']

        gsIDs = {}
        gbsIDs = {}
        
        for i in range(0, len(orgIDlist)):
            gsIDs[orgIDlist[i]] = g2 ** sIDr[i]
            gbsIDs[orgIDlist[i]] = g2 ** (b*sIDr[i])

        hb = [0]
        hbb = [0]

        for i in range(1, len(h)):
            hb.append(h[i] ** b)
            hbb.append(h[i] ** (b*b))

        g1_alpha = g1 ** alpha
        e_gg_alpha = pair(g1_alpha, g2)

        pk = {'g1': g1,
              'g2': g2,
              'g2b': g2b,
              'g1b': g1b,
              'g1bb': g1bb,
              'e_gg_alpha': e_gg_alpha,
              'h': h,
              'hb': hb,
              'hbb': hbb,
              'gsIDs': gsIDs,
              'gbsIDs': gbsIDs
        }

        msk = {
            'alpha': alpha,
            'b': b,
            's': s
        }

        self.store_ta_pk(pk, pk_filename)
        if debug:
            pkread = self.read_ta_pk(pk_filename)
            assert pk == pkread, "FAILED pk store"
        self.store_ta_msk(msk, msk_file)
        if debug:
            mskread = self.read_ta_msk(msk_file)
            assert msk == mskread, "FAILED msk store"
        return (pk, msk)

    '''
    single setup of trusted authority, should be multiple, it will
    generate pk and msk for each ta which could be used to generate 
    private key in a federated way
    '''
    def ta_setup_tree(self, pk_filename, msk_file, root):
        b = self.group.random(ZR)
        #b = self.group.init(ZR, 1)
        alpha = self.group.random(ZR)
        #alpha = self.group.init(ZR, 1)
        s = self.group.random(ZR)
        #s = self.group.init(ZR, 1)
        all_orgs = [node for node in LevelOrderIter(root)]
        
        sIDr = {}
        sID = {}

        sID[root.name] = self.group.hash(root.name, ZR) ** s
        sIDr[root.name] = 1 / sID[root.name]

        for i in range(1, len(all_orgs)):
            sID[all_orgs[i].name] = self.group.hash(all_orgs[i].name, ZR) ** sID[all_orgs[i].parent.name]
            sIDr[all_orgs[i].name] = 1 / sID[all_orgs[i].name]

        g1 = self.gp['g1']
        g1b = g1 ** b
        g1bb = g1b ** b
        g2 = self.gp['g2']
        g2b = g2 ** b
        h = self.gp['h']

        gsIDs = {}
        gbsIDs = {}

        for i in range(0, len(all_orgs)):
            gsIDs[all_orgs[i].name] = g2 ** sIDr[all_orgs[i].name]
            gbsIDs[all_orgs[i].name] = g2b ** (sIDr[all_orgs[i].name])
            
        hb = [0]
        hbb = [0]

        for i in range(1, len(h)):
            hb.append(h[i] ** b)
            hbb.append(h[i] ** (b*b))

        g1_alpha = g1 ** alpha
        e_gg_alpha = pair(g1_alpha, g2)
        pk = {'g1': g1,
              'g2': g2,
              'g2b': g2b,
              'g1b': g1b,
              'g1bb': g1bb,
              'e_gg_alpha': e_gg_alpha,
              'h': h,
              'hb': hb,
              'hbb': hbb,
              'gsIDs': gsIDs,
              'gbsIDs': gbsIDs,
              'sID': sID,
              'sIDr': sIDr
        }

        msk = {
            'alpha': alpha,
            'b': b,
            's': s
        }

        self.store_ta_pk(pk, pk_filename)
        if debug:
            pkread = self.read_ta_pk(pk_filename)
            assert pk == pkread, "FAILED pk store"
        self.store_ta_msk(msk, msk_file)
        if debug:
            mskread = self.read_ta_msk(msk_file)
            assert msk == mskread, "FAILED msk store"
        return (pk, msk)

    '''
    the ta (or multiple ta) generates private key for an org's root and the root could
    delelgate the key generation to the subordinates orgs
    the org could generate private key for users
    '''
    def org_keygen(self, attr_list, ID, ta_msk_filename, ta_pk_filename, root_org_key_filename, gp_filename, org_id):
        msk = self.read_ta_msk(ta_msk_filename)
        pk = self.read_ta_pk(gp_filename)
        alpha = msk['alpha']
        g1 = pk['g1']
        g1b = pk['g1b']
        g2 = pk['g2']
        g2b = pk['g2b']
        g1bb = pk['g1bb']
        h = pk['h']
        hb = pk['hb']
        hbb = pk['hbb']
        gbsIDs = pk['gbsIDs']
        gsIDs = pk['gsIDs']

        t = self.group.random(ZR)
        #t = self.group.init(ZR, 1)

        sID = pk['sID'][ID]
        sIDr = 1/sID

        K0 = (g1 ** alpha) * (g1bb ** (t))

        Lu = 1/(g2 ** t)
        La = 1/(g2 ** (sIDr * t))

        gbsID = g1b ** sID
        gbt = g1b ** t

        Ka = {}
        Kastr = {}
        Ku = {}
        Kustr = {}
        hstr = {}
        hx = {}
        ht = {}
        htstr = {}
        hbt = {}
        hbtstr = {}

        for attr in attr_list:
            Ka[attr] = ((g1b**sID) * hb[int(attr)]) ** (t)
            Kastr[attr] = objectToBytes(Ka[attr], self.group).decode('UTF-8')
            Ku[attr] = ((g1b ** self.group.hash(ID, ZR)) * h[int(attr)]) ** t
            Kustr[attr] = objectToBytes(Ku[attr], self.group).decode('UTF-8')
            hx[attr] = h[int(attr)]
            hstr[attr] = objectToBytes(hx[attr], self.group).decode('UTF-8')
            ht[attr] = hx[attr] ** t
            htstr[attr] = objectToBytes(ht[attr], self.group).decode('UTF-8')
            hbt[attr] = hb[int(attr)] ** t
            hbtstr[attr] = objectToBytes(hbt[attr], self.group).decode('UTF-8')

        sk = {
            'attr_list': attr_list,
            'K0': K0,
            'Lu': Lu,
            'La': La,
            'Ka': Ka,
            'Ku': Ku,
            'hx': hx,
            'hxt': ht,
            'hxbt': hbt,
            'sID': sID,
            'gbsID': gbsID,
            'gbt': gbt,
            'ID': ID,
            'org_id': org_id
        }
        
        skstr = {
            'attr_list': attr_list,
            'K0': K0,
            'Lu': Lu,
            'La': La,
            'Ka': Kastr,
            'Ku': Kustr,
            'hx': hstr,
            'hxt': htstr,
            'hxbt': hbtstr,
            'sID': sID,
            'gbsID': gbsID,
            'gbt': gbt,
            'ID': ID,
            'org_id': org_id
        }

        self.store_org_key(root_org_key_filename, skstr)
        skread = self.read_org_key(root_org_key_filename)
        if debug:
            assert sk == skread, "FAILED sk save"
        return sk

    def federated_org_keygen(self, ID, attr_list, ta_msk_file_second, pk_file, ta_sk_file_first, ta_sk_file_second, org_id):
        msk = self.read_ta_msk(ta_msk_file_second)
        alpha = msk['alpha']
        #alpha = self.group.init(ZR, 0)
        pk = self.read_ta_pk(pk_file)
        g1 = pk['g1']
        g2 = pk['g2']
        g1b = pk['g1b']
        g1bb = pk['g1bb']
        sID = pk['sID'][org_id]
        sIDr = pk['sIDr'][org_id]
        sk1 = self.read_org_key(ta_sk_file_first)
        t = self.group.random(ZR)
        h = pk['h']
        hb = pk['hb']
        gbsID = sk1['gbsID']

        K0 = (g1 ** alpha) * (g1bb ** (t))        
        K0 = sk1['K0'] * (g1 ** alpha) * (g1bb ** t)
        Lu = sk1['Lu'] * (1/(g2 ** t))
        La = sk1['La'] * (1/(g2 ** (sIDr * t)))
        gbt = sk1['gbt'] * (g1b ** t)

        Ka = {}
        Kastr = {}
        Ku = {}
        Kustr = {}
        hstr = {}
        hx = {}
        ht = {}
        htstr = {}
        hbt = {}
        hbtstr = {}

        for attr in attr_list:
            Ka[attr] = sk1['Ka'][attr] * ((g1b**sID) * hb[int(attr)]) ** (t)
            Kastr[attr] = objectToBytes(Ka[attr], self.group).decode('UTF-8')
            Ku[attr] = sk1['Ku'][attr] * ( (g1b ** self.group.hash(ID, ZR)) * h[int(attr)] ) ** t
            Kustr[attr] = objectToBytes(Ku[attr], self.group).decode('UTF-8')
            hx[attr] = h[int(attr)]
            hstr[attr] = objectToBytes(hx[attr], self.group).decode('UTF-8')
            ht[attr] = sk1['hxt'][attr] * (hx[attr] ** t)
            htstr[attr] = objectToBytes(ht[attr], self.group).decode('UTF-8')
            hbt[attr] = sk1['hxbt'][attr] * (hb[int(attr)] ** t)
            hbtstr[attr] = objectToBytes(hbt[attr], self.group).decode('UTF-8') 

        sk = {
            'attr_list': attr_list,
            'K0': K0,
            'Lu': Lu,
            'La': La,
            'Ka': Ka,
            'Ku': Ku,
            'hx': hx,
            'hxt': ht,
            'hxbt': hbt,
            'sID': sID,
            'gbsID': gbsID,
            'gbt': gbt,
            'ID': ID,
            'org_id': org_id
        }

        skstr = {
            'attr_list': attr_list,
            'K0': K0,
            'Lu': Lu,
            'La': La,
            'Ka': Kastr,
            'Ku': Kustr,
            'hx': hstr,
            'hxt': htstr,
            'hxbt': hbtstr,
            'sID': sID,
            'gbsID': gbsID,
            'gbt': gbt,
            'ID': ID,
            'org_id': org_id
        }

        self.store_org_key(ta_sk_file_second, skstr)
        skread = self.read_org_key(ta_sk_file_second)
        if debug:
            assert sk == skread, "FAILED sk save"
        return sk

    def internal_delegate(self, key_file_parent, key_file_child, childID, child_attr_list, pk_filename):
        childIDstr = childID
        key_parent = self.read_org_key(key_file_parent)
        pk = self.read_ta_pk(pk_filename)

        tprime = self.group.random(ZR)

        childID = self.group.hash(childID, ZR)
        sID = childID ** (key_parent['sID'])
        # sID = key_parent['sID']
        sIDr = 1/sID
        
        K0 = key_parent['K0'] * (pk['g1bb'] ** tprime)

        gbsID = pk['g1b'] ** sID
        gbt = (pk['g1b'] ** tprime) * key_parent['gbt']

        #assert sID == key_parent['sID'], "sID wrong"

        La = ( key_parent['La'] ** ( key_parent['sID'] * sIDr ) ) * 1/(pk['g2'] ** (sIDr * tprime))
        #assert La == key_parent['La'], "WRONG La"

        Lu = key_parent['Lu'] * (1/((pk['g2']) ** tprime))
        #assert Lu == key_parent['Lu'], "WRONG Lu"

        Ka = {}
        Kastr = {}
        Ku = {}
        Kustr = {}
        hstr = {}
        hx = {}
        ht = {}
        htstr = {}
        hbt = {}
        hbtstr = {}

        for attr in child_attr_list:
            #Ka[attr] = ((g1**sID) * h[int(attr)]) ** (b*t)
            Ka[attr] = ( ( key_parent['gbt'] * (pk['g1b'] ** tprime) ) ** sID) * key_parent['hxbt'][attr] * ( pk['hb'][int(attr)] ** tprime )
            Kastr[attr] = objectToBytes(Ka[attr], self.group).decode('UTF-8')
            # Ku[attr] = ( (g1b ** ID) * h[int(attr)] ) ** t
            Ku[attr] = ( (key_parent['gbt'] * (pk['g1b']**tprime)) ** childID ) * (key_parent['hxt'][attr] * (pk['h'][int(attr)] ** tprime) )
            Kustr[attr] = objectToBytes(Ku[attr], self.group).decode('UTF-8')
            hx[attr] = key_parent['hx'][attr]
            hstr[attr] = objectToBytes(hx[attr], self.group).decode('UTF-8')
            ht[attr] = key_parent['hxt'][attr] *(hx[attr] ** tprime)
            htstr[attr] = objectToBytes(ht[attr], self.group).decode('UTF-8')
            hbt[attr] = key_parent['hxbt'][attr] * (pk['hb'][int(attr)] ** tprime)
            hbtstr[attr] = objectToBytes(hbt[attr], self.group).decode('UTF-8')
        
        sk = {
            'attr_list': child_attr_list,
            'K0': K0,
            'Lu': Lu,
            'La': La,
            'Ka': Ka,
            'Ku': Ku,
            'hx': hx,
            'hxt': ht,
            'hxbt': hbt,
            'sID': sID,
            'gbsID': gbsID,
            'gbt': gbt,
            'ID': childIDstr,
            'org_id': childIDstr
        }

        skstr = {
            'attr_list': child_attr_list,
            'K0': K0,
            'La': La,
            'Lu': Lu,
            'Ka': Kastr,
            'Ku': Kustr,
            'hx': hstr,
            'hxt': htstr,
            'hxbt': hbtstr,
            'sID': sID,
            'gbsID': gbsID,
            'gbt': gbt,
            'ID': childIDstr,
            'org_id': childIDstr
        }

        self.store_org_key(key_file_child, skstr)
        skread = self.read_org_key(key_file_child)
        if debug:
            assert sk == skread, "FAILED sk save"
        return skstr

    def external_delegate(self, key_file_authority, key_file_user, userID, user_attr_list, pk_filename):
        userIDstr = userID
        key_authority = self.read_org_key(key_file_authority)
        pk = self.read_ta_pk(pk_filename)

        tprime = self.group.random(ZR)

        userID = self.group.hash(userID, ZR)
        sID = key_authority['sID']
        sIDr = 1/sID
        
        K0 = key_authority['K0'] * (pk['g1bb'] ** tprime)
        La = key_authority['La'] * 1/(pk['g2'] ** (sIDr * tprime))
        Lu = key_authority['Lu'] * (1/((pk['g2']) ** tprime))

        Ka = {}
        Kastr = {}
        Ku = {}
        Kustr = {}


        for attr in user_attr_list:
            Ka[attr] = ( ( key_authority['gbt'] * (pk['g1b'] ** tprime) ) ** sID) * key_authority['hxbt'][attr] * ( pk['hb'][int(attr)] ** tprime )
            Kastr[attr] = objectToBytes(Ka[attr], self.group).decode('UTF-8')
            Ku[attr] = ( (key_authority['gbt'] * (pk['g1b']**tprime)) ** userID ) * (key_authority['hxt'][attr] * (pk['h'][int(attr)] ** tprime) )
            Kustr[attr] = objectToBytes(Ku[attr], self.group).decode('UTF-8')

        
        sk = {
            'attr_list': user_attr_list,
            'K0': K0,
            'Lu': Lu,
            'La': La,
            'Ka': Ka,
            'Ku': Ku,
            'ID': userIDstr,
            'org_id': key_authority['ID']
        }

        skstr = {
            'attr_list': user_attr_list,
            'K0': K0,
            'La': La,
            'Lu': Lu,
            'Ka': Kastr,
            'Ku': Kustr,
            'ID': userIDstr,
            'org_id': key_authority['ID']
        }

        self.store_user_key(key_file_user, skstr)
        skread = self.read_user_key(key_file_user)
        if debug:
            assert sk == skread, "FAILED sk save"
        return skstr

    def encrypt(self, pk_filename, msg, policy_str, revIDlist_u, non_revIDlist_a, ctxt_filename):
        """
         Encrypt a message M under a monotone span program.
        """
        if debug:
            print('Encryption algorithm:\n')

        policy = self.util1.createPolicy(policy_str)
        mono_span_prog = self.util2.convert_policy_to_msp(policy)
        num_cols = self.util2.len_longest_row
      
        pk = self.read_global_public_params(pk_filename)

        # pick randomness
        u = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            u.append(rand)
        s = u[0]    # shared secret

        miuus = []
        miuu = 0
        miua = self.group.random(ZR)
        for i in range(0, len(revIDlist_u)):
          ru = self.group.random(ZR)
          miuus.append(ru)
          miuu = miuu + ru
        
        miu = miuu + miua
             
        # for testing authority
        c_m = (pk['e_gg_alpha'] ** (miu*s)) * msg
        c0 = pk['g2'] ** (miu*s)

        # for multiple revoked identities
        C_u_star = {}
        C_u_prime = {}

        C_a_star = {}
        C_a_prime = {}

        ind = 0

        while ind < len(revIDlist_u):
          C_u_star[ind] = {}
          C_u_prime[ind] = {}
          ind = ind + 1
        
        ind = 0
        while ind < len(non_revIDlist_a):
          C_a_star[non_revIDlist_a[ind]] = {}
          ind = ind + 1
        
        for attr, row in mono_span_prog.items():
            ind = 0
            cols = len(row)
            sum = 0

            for i in range(cols):
                sum += row[i] * u[i]

            attr_stripped = self.util2.strip_index(attr)
            
            while ind < len(revIDlist_u):
              c_attr_u = (pk['g2b'] ** (miuus[ind]*sum)) 
              d_attr_u = ((pk['g1bb'] ** revIDlist_u[ind]) * pk['hb'][int(attr_stripped)]) ** (miuus[ind]*sum)
              C_u_star[ind][attr] = objectToBytes(c_attr_u, self.group).decode('UTF-8')
              C_u_prime[ind][attr] = objectToBytes(d_attr_u, self.group).decode('UTF-8')
              ind = ind+1
            
            ind = 0
            while ind < len(non_revIDlist_a):
               C_a_star[non_revIDlist_a[ind]][attr] = objectToBytes(pk['gbsIDs'][non_revIDlist_a[ind]] ** (miua*sum ), self.group).decode('UTF-8')
               ind =  ind + 1

            C_a_prime[attr] = objectToBytes(pk['hbb'][int(attr_stripped)] ** (miua*sum ), self.group).decode('UTF-8')

        revIDbytes = []
        for revID in revIDlist_u:
          revIDbytes.append(objectToBytes(revID, self.group).decode('UTF-8'))
        
        ctxt_store = {'policy': policy_str, 'c0': c0, 'c_m': c_m, 
        'revIDlist_u': revIDbytes, 'non_revIDlist_a': non_revIDlist_a,'C_u_star': C_u_star, 'C_u_prime': C_u_prime,
        'C_a_star': C_a_star, 'C_a_prime': C_a_prime}

        # datstore = self.set_ctxt(ctxt_store)
        # rec_ctxt = self.get_ctxt(datstore)
        # print("ctxt_store['revIDlist_u'] ", ctxt_store['revIDlist_u'])
        # print("rec_ctx revIDlsit_u ", rec_ctxt['revIDlist_u'])
        # print("ctxt_stroe == rec_ctxt is ", ctxt_store['revIDlist_u'] == rec_ctxt['revIDlist_u'])
        self.store_ctxt(ctxt_filename, ctxt_store) 
        return self.set_ctxt(ctxt_store)

    def decrypt(self, ctxt, key):
        """
         Decrypt ciphertext ctxt with key key.
        """
        nodes = self.util1.prune(ctxt['policy'], key['attr_list'])

        ID = self.group.hash(key['ID'], ZR)

        if not nodes or (ID in ctxt['revIDlist_u']) or (not key['org_id'] in ctxt['non_revIDlist_a']):
            print ("Policy not satisfied.")
            return None

        prodGG = [1]*len(ctxt['revIDlist_u'])
        prodGGT = [1]*len(ctxt['revIDlist_u'])

        i = 0
        num = len(ctxt['revIDlist_u'])

        while i < num:
          for node in nodes:
              attr = node.getAttributeAndIndex()
              attr_stripped = self.util1.strip_index(attr)
              prodGG[i] *= ctxt['C_u_prime'][i][attr]
              prodGGT[i] *= pair(key['Ku'][attr_stripped], ctxt['C_u_star'][i][attr])
          i = i+1

        itmm = []
        ind = 0
        while ind < num:
          x = (pair(prodGG[ind], key['Lu']) * prodGGT[ind]) ** (1/(self.group.hash(key['ID'], ZR)-ctxt['revIDlist_u'][ind]))
          itmm.append(x)
          ind = ind+1

        prod_u = 1
        for item in itmm:
          prod_u *= item
    
        prodG = 1
        prodGT = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util1.strip_index(attr)
            prodG *= ctxt['C_a_prime'][attr]
            prodGT *= pair( key['Ka'][attr_stripped], ctxt['C_a_star'][key['org_id']][attr])
        
        prod_a = pair(prodG, key['La']) * prodGT

        return (ctxt['c_m'] * prod_u * prod_a / (pair(key['K0'], ctxt['c0'])))

    def decrypt_file(self, ctxt_filename, key_filename):
        """
         Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        key = self.read_user_key(key_filename)
  
        ctxt = self.read_ctxt(ctxt_filename)
        ctxt['policy'] = self.util2.createPolicy( ctxt['policy'] )

        return self.decrypt(ctxt, key)
    
    def decrypt_ctxt_json(self, ctxt_store, key_filename):
        if debug:
            print("Decryption algorithm \n")
        key = self.read_user_key(key_filename)
        ctxt = self.get_ctxt(ctxt_store)
        ctxt['policy'] = self.util.createPolicy(ctxt['policy'])
        return self.decrypt(ctxt, key)

    def read_attr_dict(self, filename):
        with open(filename, 'r') as f:
            json_dict = json.load(f)
        return json_dict

# def main():
#   #====================================== sepearate ABE and sym enc ==============================#
#     if unittest:
#         # set up global parameters
#         groupObj = PairingGroup('SS512')
#         cpabe = IDABE(groupObj)
#         gpfile = "global.param"
#         cpabe.setupGP(gpfile)
#
#         # attr_str_list is the string format of all attributes
#         attr_dict = cpabe.read_attr_dict("attributes_map.json")
#         # set up the system, generate private key in a federated way
#         TAset = ['ta1', 'ta2', 'ta3']
#
#         # this is the example access policy
#         access_policy = '((attr1 and attr2) or (attr2 and attr3) or (attr3 and attr4) or (attr5 and attr6))'
#         for attr, num in attr_dict.items():
#             access_policy = access_policy.replace(attr, num)
#
#         # the example AES key which will be encrypted by ABE scheme
#         symk = groupObj.random(GT)
#         rand_key_bytes = objectToBytes(symk, cpabe.group)
#         key = sha256(rand_key_bytes).digest()
#         cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
#         # the example message to be encrypted by AES
#         msg = "test message"
#         ciphertext = cipher.encrypt(msg)
#
#         print("ciphertext is ", ciphertext)
#
#         # parameters of each trusted authority
#         ta_msk_filenames = {"ta1": "ta1.msk", "ta2": "ta2.msk", "ta3": "ta3.msk"}
#         ta_pk_filenames = {"ta1": "ta1.pk", "ta2": "ta2.pk", "ta3": "ta3.pk"}
#         # file for saving user's secret key
#         key_filename = "test_user.sk"
#         # file for saving ciphertext
#         ctxt_filename = "ctxt.json"
#
#         attr_str_list = ['attr1', 'attr2', 'attr3', 'attr4', 'attr5', 'attr6', 'attr7', 'attr8', 'attr9', 'attr10']
#
#         #================================== revoked identities set up ====================
#         # revoked users
#         revID1 = cpabe.group.hash("orgx", ZR)
#         revID2 = cpabe.group.hash("orgy", ZR)
#         revID3 = cpabe.group.hash("orgz", ZR)
#         revIDlist_u = [revID1, revID2, revID3]
#         # revoked authorities
#         non_revIDlist_a = ['org1', 'org2', 'org3']
#
#         #============================ Tree structure ==============================
#         root_org = "org1"
#         root = Node("org1")
#         org2 = Node("org2", parent = root)
#         org3 = Node("org3", parent = root)
#         org4 = Node("org4", parent = root)
#         org5 = Node("org5", parent = org2)
#         org6 = Node("org6", parent = org2)
#         print(Fore.BLUE + RenderTree(root, style=AsciiStyle()).by_attr())
#
#         #=========================== set global parameters based on the tree structure =====================
#         print(Fore.RED + 'Federated Setup test \n')
#         print(Style.RESET_ALL)
#         for ta in TAset:
#             cpabe.ta_setup_tree(ta_pk_filenames[ta], ta_msk_filenames[ta], root)
#
#         for i in range(1, len(TAset)):
#             ta_first = "ta" + str(i)
#             ta_second = "ta" + str(i+1)
#             cpabe.federated_setup(ta_pk_filenames[ta_first], ta_pk_filenames[ta_second],
#                 ta_msk_filenames[ta_second], ta_msk_filenames[ta_first], root)
#
#         attr_assigned_str = attr_str_list
#         attr_assigned = []
#         for attr in attr_assigned_str:
#           attr_assigned.append(attr_dict[attr])
#
#         root_org_key_filename = "org1.sk"
#
#         # generate private key for a root organization
#         cpabe.org_keygen(attr_assigned, root_org, ta_msk_filenames['ta3'], ta_pk_filenames['ta3'],
#             root_org_key_filename, ta_pk_filenames['ta3'], root_org)
#         cpabe.encrypt( ta_pk_filenames['ta3'], symk, access_policy,
#             revIDlist_u, non_revIDlist_a, ctxt_filename)
#
#         rec_msg = cpabe.decrypt_file(ctxt_filename, root_org_key_filename)
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # # ============================= publish the global public parameters, generated above =========================
#         # global_public_param_file = "gpublic.json"
#         # cpabe.save_global_public_params(global_public_param_file, ta_pk_filenames[TAset[-1]])
#
#         # #=========================== key generation for root organiation org1 ========================
#         # print(Fore.RED + "root org key generation and decryption test \n")
#         # print(Style.RESET_ALL)
#         # root_org_key_filename = "org1.sk"
#         # attr_assigned_str = attr_str_list
#         # attr_assigned = []
#         # for attr in attr_assigned_str:
#         #   attr_assigned.append(attr_dict[attr])
#
#         # # generate private key for a root organization
#         # cpabe.org_keygen(attr_assigned, root_org, ta_msk_filenames['ta3'], global_public_param_file,
#         #     root_org_key_filename, gpfile, root_org)
#         # cpabe.encrypt( global_public_param_file, symk, access_policy,
#         #     revIDlist_u, non_revIDlist_a, ctxt_filename)
#
#         # rec_msg = cpabe.decrypt(ctxt_filename, root_org_key_filename)
#         # if rec_msg:
#         #     assert symk == rec_msg, "FAILED DECRYPTION"
#         #     print("decryption successful")
#         #     dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#         #     deckey = sha256(dec_key_bytes).digest()
#         #     deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#         #     print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # # ============================= root - user external delegation test ====================================
#         print(Fore.RED + "root - user external delegation test \n")
#         print(Style.RESET_ALL)
#         key_file_user = "test_user.sk"
#         userID = "test_user"
#         user_attr_list = []
#         user_assigned_attr = ['attr3', 'attr4']
#         for attr in user_assigned_attr:
#             user_attr_list.append(attr_dict[attr])
#
#         cpabe.external_delegate(root_org_key_filename,
#             key_file_user, userID, user_attr_list, ta_pk_filenames['ta3'])
#         rec_msg = cpabe.decrypt_file(ctxt_filename, key_file_user)
#
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # ============================== internal delegation 1 test ==================================
#         print(Fore.RED + "internal delegation 1 test \n")
#         print(Style.RESET_ALL)
#         key_file_parent = root_org_key_filename
#         key_file_child = "org3.sk"
#         childID = "org3"
#         child_assigned_attr = ['attr1', 'attr2', 'attr3', 'attr4']
#         child_attr_list = []
#         for attr in child_assigned_attr:
#             child_attr_list.append(attr_dict[attr])
#
#         cpabe.internal_delegate(key_file_parent, key_file_child, childID,
#             child_attr_list, ta_pk_filenames['ta3'])
#         rec_msg = cpabe.decrypt_file(ctxt_filename, key_file_child)
#
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # ============================= inner org - user external delegation test ====================================
#         print(Fore.RED + "inner org - user external delegation test \n")
#         print(Style.RESET_ALL)
#         key_file_user = "test_user.sk"
#         userID = "test_user"
#         user_attr_list = []
#         user_assigned_attr = ['attr3', 'attr4']
#         for attr in user_assigned_attr:
#             user_attr_list.append(attr_dict[attr])
#
#         cpabe.external_delegate(key_file_child, key_file_user, userID, user_attr_list, ta_pk_filenames['ta3'])
#         rec_msg = cpabe.decrypt_file(ctxt_filename, key_file_user)
#
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # ============================== internal delegation 2 test ==================================
#         print(Fore.RED + "internal delegation 2 test \n")
#         print(Style.RESET_ALL)
#         key_file_parent = root_org_key_filename
#         key_file_child = "org2.sk"
#         childID = "org2"
#         child_assigned_attr = ['attr5', 'attr6']
#         child_attr_list = []
#         for attr in child_assigned_attr:
#             child_attr_list.append(attr_dict[attr])
#
#         cpabe.internal_delegate(key_file_parent, key_file_child, childID, child_attr_list, ta_pk_filenames['ta3'])
#         rec_msg = cpabe.decrypt_file(ctxt_filename, key_file_child)
#
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # ============================= org2, org3 - user external delegation ========================
#         print(Fore.RED + "org2, org3 - user external delegation\n")
#         print(Style.RESET_ALL)
#         most_closest_ancestor = util.commonancestors(org2, org3)[-1].name
#         key_file_org = most_closest_ancestor + ".sk"
#
#         key_file_user = "test_user.sk"
#         userID = "test_user"
#         user_attr_list = []
#         user_assigned_attr = ['attr3', 'attr5', 'attr6']
#         for attr in user_assigned_attr:
#             user_attr_list.append(attr_dict[attr])
#
#         cpabe.external_delegate(key_file_org, key_file_user, userID, user_attr_list, ta_pk_filenames['ta3'])
#         rec_msg = cpabe.decrypt_file(ctxt_filename, key_file_user)
#
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # =============================== Federated set up =================================
#         print(Fore.RED + 'Federated Setup test \n')
#         print(Style.RESET_ALL)
#
#         for ta in TAset:
#             cpabe.ta_setup_tree(ta_pk_filenames[ta], ta_msk_filenames[ta], root)
#
#         for i in range(1, len(TAset)):
#             ta_first = "ta" + str(i)
#             ta_second = "ta" + str(i+1)
#             cpabe.federated_setup1(ta_pk_filenames[ta_first], ta_pk_filenames[ta_second],
#                 ta_msk_filenames[ta_second], root)
#
#         # ================== test federated key geneation
#         ta_sk_filenames = {"ta1": "ta1.org.sk", "ta2": "ta2.org.sk", "ta3": "ta3.org.sk"}
#
#         for i in range(1, len(TAset) + 1):
#             ta_name = "ta" + str(i)
#             cpabe.org_keygen(attr_assigned, root_org, ta_msk_filenames[ta_name], ta_pk_filenames[ta_name],
#             ta_sk_filenames[ta_name], ta_pk_filenames["ta3"], root_org)
#
#         for i in range(1, len(TAset)):
#             ta_first = "ta" + str(i)
#             ta_second = "ta" + str(i+1)
#             cpabe.federated_org_keygen(root_org, attr_assigned, ta_msk_filenames[ta_second], ta_pk_filenames["ta3"],
#                 ta_sk_filenames[ta_first], ta_sk_filenames[ta_second], root_org)
#
#         cpabe.encrypt( ta_pk_filenames['ta3'], symk, access_policy,
#             revIDlist_u, non_revIDlist_a, ctxt_filename)
#
#         rec_msg = cpabe.decrypt_file(ctxt_filename, ta_sk_filenames['ta3'])
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#         # ============================= inner org - user external delegation test ====================================
#         print(Fore.RED + "inner org - user external delegation test \n")
#         print(Style.RESET_ALL)
#         key_file_user = "test_user.sk"
#         userID = "test_user"
#         user_attr_list = []
#         user_assigned_attr = ['attr3', 'attr4']
#         for attr in user_assigned_attr:
#             user_attr_list.append(attr_dict[attr])
#
#         cpabe.external_delegate(ta_sk_filenames['ta3'], key_file_user, userID, user_attr_list, ta_pk_filenames['ta3'])
#         rec_msg = cpabe.decrypt_file(ctxt_filename, key_file_user)
#
#         if rec_msg:
#             assert symk == rec_msg, "FAILED DECRYPTION"
#             print("decryption successful")
#             dec_key_bytes = objectToBytes(rec_msg, cpabe.group)
#             deckey = sha256(dec_key_bytes).digest()
#             deccipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(deckey)
#             print("decrypted message is ", deccipher.decrypt(ciphertext).decode('UTF_8'))
#
#
# if __name__ == "__main__":
#     debug = True
#     unittest = True
#     message_enc = True
#     file_enc = True
#     main()
   