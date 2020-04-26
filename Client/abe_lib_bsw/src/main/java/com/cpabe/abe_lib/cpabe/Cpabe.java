package com.cpabe.abe_lib.cpabe;

import com.cpabe.abe_lib.bsw.Bswabe;
import com.cpabe.abe_lib.bsw.BswabeCph;
import com.cpabe.abe_lib.bsw.BswabeCphKey;
import com.cpabe.abe_lib.bsw.BswabeElementBoolean;
import com.cpabe.abe_lib.bsw.BswabeMsk;
import com.cpabe.abe_lib.bsw.BswabePrv;
import com.cpabe.abe_lib.bsw.BswabePub;
import com.cpabe.abe_lib.bsw.SerializeUtils;
import com.cpabe.abe_lib.cpabe.policy.LangPolicy;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import it.unisa.dia.gas.jpbc.Element;

public class Cpabe {

	/**
	 * @param
	 * @author Junwei Wang(wakemecn@gmail.com)
	 */

	//存储临时的公钥密钥用来委派
	BswabePub pub_tmp;
	BswabePrv prv_tmp;
	//ArrayList<BswabePrv> prv_tmp = new ArrayList<BswabePrv>();

	public void setup(String pubfile, String mskfile) throws IOException,
			ClassNotFoundException {
		byte[] pub_byte, msk_byte;
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();
		Bswabe.setup(pub, msk);

		//保存公钥用来delegate
		pub_tmp = pub;

		/* store BswabePub into mskfile */
		pub_byte = SerializeUtils.serializeBswabePub(pub);
		Common.spitFile(pubfile, pub_byte);

		/* store BswabeMsk into mskfile */
		msk_byte = SerializeUtils.serializeBswabeMsk(msk);
		Common.spitFile(mskfile, msk_byte);
	}

	public void keygen(String pubfile, String prvfile, String mskfile, String[] attr_str) throws NoSuchAlgorithmException, IOException {
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

		//保存prv用来delegate
		//prv_tmp.add(prv);
		prv_tmp = prv;

		/* store BswabePrv into prvfile */
		prv_byte = SerializeUtils.serializeBswabePrv(prv);
		Common.spitFile(prvfile, prv_byte);
	}

	public void  delegate(String prvfile_delegate, String[] attr_subset) throws Exception {
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

}
