package com.cpabe.abe_lib.cpabe;

import com.cpabe.abe_lib.bsw.Bswabe;
import com.cpabe.abe_lib.bsw.BswabeCph;
import com.cpabe.abe_lib.bsw.BswabeCphKey;
import com.cpabe.abe_lib.bsw.BswabeElementBoolean;
import com.cpabe.abe_lib.bsw.BswabeMsk;
import com.cpabe.abe_lib.bsw.BswabePrv;
import com.cpabe.abe_lib.bsw.BswabePub;
import com.cpabe.abe_lib.bsw.SerializeUtils;
import com.cpabe.abe_lib.bsw.Node;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;


import it.unisa.dia.gas.jpbc.Element;

public class Cpabe {

	/**
	 * @param
	 * @author Junwei Wang(wakemecn@gmail.com)
	 */

	//Store the temporary pub and prv keys for delegate
	BswabePub pub_tmp;
	BswabePrv prv_tmp;
	//ArrayList<BswabePrv> prv_tmp = new ArrayList<BswabePrv>();
	HashMap<String, Element> gp = Bswabe.gsetup();

	public void setup(String pubfile, String mskfile) throws IOException {
		byte[] pub_byte, msk_byte;
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();

		//call bsw lib to set up public and private keys
		Bswabe.setup(pub, msk);

		//Store a temp public key cache for delegation
		pub_tmp = pub;

		/* store BswabePub into mskfile */
		pub_byte = SerializeUtils.serializeBswabePub(pub);
		Common.spitFile(pubfile, pub_byte);

		/* store BswabeMsk into mskfile */
		msk_byte = SerializeUtils.serializeBswabeMsk(msk);
		Common.spitFile(mskfile, msk_byte);
	}

	public void keygen(String pubfile, String prvfile, String mskfile, String[] attr_str) throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
		BswabePub pub;
		BswabeMsk msk;
		byte[] pub_byte, msk_byte, prv_byte;

		/* get BswabePub from pubfile */
		pub_byte = Common.suckFile(pubfile);
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		/* get BswabeMsk from mskfile */
		msk_byte = Common.suckFile(mskfile);
		msk = SerializeUtils.unserializeBswabeMsk(pub, msk_byte);

		//String[] attr_arr = LangPolicy.parseAttribute(attr_str);
		BswabePrv prv = Bswabe.keygen(pub, msk, attr_str);

		//save the prev key file for delegate
		//prv_tmp.add(prv);
		prv_tmp = prv;

		/* store BswabePrv into prvfile */
		prv_byte = SerializeUtils.serializeBswabePrv(prv);
		Common.spitFile(prvfile, prv_byte);
	}

	public void delegate(String prvfile_delegate, String[] attr_subset) throws Exception {
		BswabePrv prv_delegate;
		prv_delegate = Bswabe.delegate(pub_tmp, prv_tmp, attr_subset);
		byte[] prvfile_delegate_byte = SerializeUtils.serializeBswabePrv(prv_delegate);
		Common.spitFile(prvfile_delegate, prvfile_delegate_byte);
	}

	public void enc(String pubfile, String policy, String inputfile, String encfile) throws Exception {
		BswabePub pub;
		BswabeCph cph;
		BswabeCphKey keyCph;
		byte[] plt;
		byte[] cphBuf;
		byte[] aesBuf;
		byte[] pub_byte;
		Element m;

		/* get BswabePub from pubfile */
		pub_byte = Common.suckFile(pubfile);
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		keyCph = Bswabe.enc(pub, policy);
		cph = keyCph.cph;
		m = keyCph.key;
		System.err.println("m = " + m.toString());

		if (cph == null) {
			System.out.println("Error happened in enc");
			System.exit(0);
		}

		cphBuf = SerializeUtils.bswabeCphSerialize(cph);

		/* read file to encrypted */
		plt = Common.suckFile(inputfile);
		byte[] cpabeKey = m.toBytes();
		aesBuf = AESCoder.encrypt(cpabeKey, plt);
		// PrintArr("element: ", m.toBytes());
		Common.writeCpabeFile(encfile, cphBuf, aesBuf);
	}

	public boolean dec(String pubfile, String prvfile, String encfile, String decfile) throws Exception {
		byte[] aesBuf, cphBuf;
		byte[] plt;
		byte[] prv_byte;
		byte[] pub_byte;
		byte[][] tmp;
		BswabeCph cph;
		BswabePrv prv;
		BswabePub pub;

		/* get BswabePub from pubfile */
		pub_byte = Common.suckFile(pubfile);
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		/* read ciphertext */
		tmp = Common.readCpabeFile(encfile);
		aesBuf = tmp[0];
		cphBuf = tmp[1];
		cph = SerializeUtils.bswabeCphUnserialize(pub, cphBuf);

		/* get BswabePrv form prvfile */
		prv_byte = Common.suckFile(prvfile);
		prv = SerializeUtils.unserializeBswabePrv(pub, prv_byte);

		BswabeElementBoolean beb = Bswabe.dec(pub, prv, cph);
		System.err.println("e = " + beb.e.toString());
		if (beb.b) {
			byte[] cpabeKey = beb.e.toBytes();
			plt = AESCoder.decrypt(cpabeKey, aesBuf);
			Common.spitFile(decfile, plt);
			return true;
		} else {
			System.exit(0);
			return false;
		}
	}

	public Node treeStruc(){
		Node org1 = new Node("org1");
		Node org2 = new Node("org2");
		Node org3 = new Node("org3");
		Node org4 = new Node("org4");
		Node org5 = new Node("org5");
		Node org6 = new Node("org6");

		org1.addChild(org2);
		org1.addChild(org3);
		org1.addChild(org4);
		org2.addChild(org5);
		org2.addChild(org6);

//Generated Tree Structure
//        org1
//         |-- org2
//         |   |-- org5
//         |   +-- org6
//         |-- org3
//         +-- org4

		return org1;
	}

	public void ta_setup_tree(String pubfile, String mskfile, String prvfile, Node rootNode) throws IOException, NoSuchAlgorithmException {
		byte[] pub_byte, msk_byte, prv_byte;
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();

		Bswabe.ta_setup_tree(pub, msk, rootNode, gp);

		pub_byte = SerializeUtils.serializeBswabePub(pub);
		Common.spitFile(pubfile, pub_byte);

		msk_byte = SerializeUtils.serializeBswabeMsk(msk);
		Common.spitFile(mskfile, msk_byte);

		BswabePrv prv = Bswabe.keygen(pub, msk, new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"});

		prv_byte = SerializeUtils.serializeBswabePrv(prv);
		Common.spitFile(prvfile, prv_byte);
	}

	public void federated_setup1(String pubfile_pk_file1, String pubfile_pk_file2, String mskfile_msk_file2,Node rootNode) throws IOException, NoSuchAlgorithmException, ClassNotFoundException {
		byte[] pub_byte1;
		byte[] pub_byte2;
		byte[] msk_byte2;
		BswabePub pub1;
		BswabePub pub2;
		BswabeMsk msk2;

		//fist public file
		pub_byte1 = Common.suckFile(pubfile_pk_file1);
		pub1 = SerializeUtils.unserializeBswabePub(pub_byte1);

		//second public file and msk file
		pub_byte2 = Common.suckFile(pubfile_pk_file2);
		pub2 = SerializeUtils.unserializeBswabePub(pub_byte2);

		msk_byte2 = Common.suckFile(mskfile_msk_file2);
		msk2 = SerializeUtils.unserializeBswabeMsk(pub2,msk_byte2);

		Bswabe.federated_setup1(pub1, pub2, msk2, rootNode, gp);

		pub_byte2 = SerializeUtils.serializeBswabePub(pub2);
		Common.spitFile(pubfile_pk_file2, pub_byte2);
	}

	public void org_keygen(String[] attr_assigned, Node root, String mskfile,String pubfile, String prvfile) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
		byte[] pub_byte;
		byte[] msk_byte;
		byte[] prv_byte;
		BswabePub pub;
		BswabeMsk msk;
		BswabePrv prv;

		pub_byte = Common.suckFile(pubfile);
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		msk_byte = Common.suckFile(mskfile);
		msk = SerializeUtils.unserializeBswabeMsk(pub, msk_byte);

		prv_byte = Common.suckFile(prvfile);
		prv = SerializeUtils.unserializeBswabePrv(pub, prv_byte);

		Bswabe.org_keygen(attr_assigned, root, msk, pub, prv, gp);

		prv_byte = SerializeUtils.serializeIrcpabePrv(prv);
		Common.spitFile(prvfile, prv_byte);
	}

	public void federated_org_keygen(String ID, String[] attr_list, String ta_msk_file_second, String pk_file, String ta_sk_file_first, String ta_sk_file_second, String org_id) throws IOException, ClassNotFoundException {
		byte[] pub_byte;
		byte[] msk_byte;
		byte[] prv_byte_first;
		byte[] prv_byte_second;


		BswabeMsk msk_second;
		BswabePub pub;
		BswabePrv prv_first;
		BswabePrv prv_second;

		pub_byte = Common.suckFile(pk_file);
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		msk_byte = Common.suckFile(ta_msk_file_second);
		msk_second = SerializeUtils.unserializeBswabeMsk(pub, msk_byte);

		prv_byte_first = Common.suckFile(ta_sk_file_first);
		prv_first = SerializeUtils.unserializeIrcpabePrv(pub, prv_byte_first);

		prv_byte_second = Common.suckFile(ta_sk_file_second);
		prv_second = SerializeUtils.unserializeIrcpabePrv(pub, prv_byte_second);
	}
}
