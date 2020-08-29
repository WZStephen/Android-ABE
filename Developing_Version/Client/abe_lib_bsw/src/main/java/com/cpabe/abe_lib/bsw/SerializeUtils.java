package com.cpabe.abe_lib.bsw;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SerializeUtils {

	/* Method has been test okay */
	public static void serializeElement(ArrayList<Byte> arrlist, Element e) {
		byte[] arr_e = e.toBytes();
		serializeUint32(arrlist, arr_e.length);
		byteArrListAppend(arrlist, arr_e);
	}

	/* Method has been test okay */
	public static int unserializeElement(byte[] arr, int offset, Element e) {
		int len;
		int i;
		byte[] e_byte;

		len = unserializeUint32(arr, offset);
		e_byte = new byte[(int) len];
		offset += 4;
		//offset += 8;
		for (i = 0; i < len; i++)
			e_byte[i] = arr[offset + i];
		e.setFromBytes(e_byte);

		return (int) (offset + len);
	}

	public static void serializeString(ArrayList<Byte> arrlist, String s) {
		byte[] b = s.getBytes();
		serializeUint32(arrlist, b.length);
		byteArrListAppend(arrlist, b);
	}

	/*
	 * Usage:
	 * 
	 * StringBuffer sb = new StringBuffer("");
	 * 
	 * offset = unserializeString(arr, offset, sb);
	 * 
	 * String str = sb.substring(0);
	 */
	public static int unserializeString(byte[] arr, int offset, StringBuffer sb) {
		int i;
		int len;
		byte[] str_byte;
	
		len = unserializeUint32(arr, offset);
		offset += 4;
		str_byte = new byte[len];
		for (i = 0; i < len; i++)
			str_byte[i] = arr[offset + i];
	
		sb.append(new String(str_byte));
		return offset + len;
	}

	public static byte[] serializeBswabePub(BswabePub pub) throws IOException {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();

		serializeString(arrlist, pub.pairingDesc);
		serializeElement(arrlist, pub.g);
		serializeElement(arrlist, pub.h);
		serializeElement(arrlist, pub.gp);
		serializeElement(arrlist, pub.g_hat_alpha);

		int pubCompsLen, i;
		pubCompsLen = pub.Ircpabe_comp.size();
		serializeUint32(arrlist, pubCompsLen);

		for (i = 0; i < pubCompsLen; i++) {
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).g1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).g1b);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).g1bb);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).g2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).g2b);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).e_gg_alpha);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h3);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h4);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h5);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h6);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h7);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h8);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h9);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).h10);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gsIDs_org1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gsIDs_org2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gsIDs_org3);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gsIDs_org4);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gsIDs_org5);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gsIDs_org6);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gbsIDs_org1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gbsIDs_org2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gbsIDs_org3);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gbsIDs_org4);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gbsIDs_org5);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).gbsIDs_org6);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sID_org1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sID_org2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sID_org3);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sID_org4);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sID_org5);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sID_org6);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sIDr_org1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sIDr_org2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sIDr_org3);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sIDr_org4);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sIDr_org5);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).sIDr_org6);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb3);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb4);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb5);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb6);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb7);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb8);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb9);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hb10);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb1);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb2);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb3);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb4);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb5);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb6);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb7);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb8);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb9);
			serializeElement(arrlist, pub.Ircpabe_comp.get(i).hbb10);
		}
		return Byte_arr2byte_arr(arrlist);
	}

	public static BswabePub unserializeBswabePub(byte[] b) throws IOException, ClassNotFoundException {
		BswabePub pub;
		int offset;

		pub = new BswabePub();
		offset = 0;

		StringBuffer sb = new StringBuffer("");
		offset = unserializeString(b, offset, sb);
		pub.pairingDesc = sb.substring(0);

		CurveParameters params = new DefaultCurveParameters().load(new ByteArrayInputStream(pub.pairingDesc.getBytes()));
		pub.p = PairingFactory.getPairing(params);
		Pairing pairing = pub.p;

		pub.g = pairing.getG1().newElement();
		pub.h = pairing.getG1().newElement();
		pub.gp = pairing.getG2().newElement();
		pub.g_hat_alpha = pairing.getGT().newElement();

		offset = unserializeElement(b, offset, pub.g);
		offset = unserializeElement(b, offset, pub.h);
		offset = unserializeElement(b, offset, pub.gp);
		offset = unserializeElement(b, offset, pub.g_hat_alpha);

		pub.Ircpabe_comp = new ArrayList<>();
		int len = unserializeUint32(b, offset);
		for(int i = 0; i<len; i++){
			Ircpabe in = new Ircpabe();
			in.g1 =pairing.getG1().newElement();
			in.g1b = pairing.getG1().newElement();
			in.g1bb = pairing.getG1().newElement();
			in.g2 = pairing.getG2().newElement();
			in.g2b = pairing.getG2().newElement();
			in.e_gg_alpha = pairing.getGT().newElement();
			in.h1 = pairing.getG1().newElement();
			in.h2 = pairing.getG1().newElement();
			in.h3 = pairing.getG1().newElement();
			in.h4 = pairing.getG1().newElement();
			in.h5 = pairing.getG1().newElement();
			in.h6 = pairing.getG1().newElement();
			in.h7 = pairing.getG1().newElement();
			in.h8 = pairing.getG1().newElement();
			in.h9 = pairing.getG1().newElement();
			in.h10 = pairing.getG1().newElement();
			in.gsIDs_org1 = pairing.getG1().newElement();
			in.gsIDs_org2 = pairing.getG1().newElement();
			in.gsIDs_org3 = pairing.getG1().newElement();
			in.gsIDs_org4 = pairing.getG1().newElement();
			in.gsIDs_org5 = pairing.getG1().newElement();
			in.gsIDs_org6 = pairing.getG1().newElement();
			in.gbsIDs_org1 = pairing.getG1().newElement();
			in.gbsIDs_org2 = pairing.getG1().newElement();
			in.gbsIDs_org3 = pairing.getG1().newElement();
			in.gbsIDs_org4 = pairing.getG1().newElement();
			in.gbsIDs_org5 = pairing.getG1().newElement();
			in.gbsIDs_org6 = pairing.getG1().newElement();
			in.sID_org1 = pairing.getZr().newElement();
			in.sID_org2 = pairing.getZr().newElement();
			in.sID_org3 = pairing.getZr().newElement();
			in.sID_org4 = pairing.getZr().newElement();
			in.sID_org5 = pairing.getZr().newElement();
			in.sID_org6 = pairing.getZr().newElement();
			in.sIDr_org1 = pairing.getZr().newElement();
			in.sIDr_org2 = pairing.getZr().newElement();
			in.sIDr_org3 = pairing.getZr().newElement();
			in.sIDr_org4 = pairing.getZr().newElement();
			in.sIDr_org5 = pairing.getZr().newElement();
			in.sIDr_org6 = pairing.getZr().newElement();
			in.hb1 = pairing.getG1().newElement();
			in.hb2 = pairing.getG1().newElement();
			in.hb3 = pairing.getG1().newElement();
			in.hb4 = pairing.getG1().newElement();
			in.hb5 = pairing.getG1().newElement();
			in.hb6 = pairing.getG1().newElement();
			in.hb7 = pairing.getG1().newElement();
			in.hb8 = pairing.getG1().newElement();
			in.hb9 = pairing.getG1().newElement();
			in.hb10 = pairing.getG1().newElement();
			in.hbb1 = pairing.getG1().newElement();
			in.hbb2 = pairing.getG1().newElement();
			in.hbb3 = pairing.getG1().newElement();
			in.hbb4 = pairing.getG1().newElement();
			in.hbb5 = pairing.getG1().newElement();
			in.hbb6 = pairing.getG1().newElement();
			in.hbb7 = pairing.getG1().newElement();
			in.hbb8 = pairing.getG1().newElement();
			in.hbb9 = pairing.getG1().newElement();
			in.hbb10 = pairing.getG1().newElement();

			offset += 4;
			offset = unserializeElement(b, offset, in.g1);
			offset = unserializeElement(b, offset, in.g1b);
			offset = unserializeElement(b, offset, in.g1bb);
			offset = unserializeElement(b, offset, in.g2);
			offset = unserializeElement(b, offset, in.g2b);
			offset = unserializeElement(b, offset, in.e_gg_alpha);
			offset = unserializeElement(b, offset, in.h1);
			offset = unserializeElement(b, offset, in.h2);
			offset = unserializeElement(b, offset, in.h3);
			offset = unserializeElement(b, offset, in.h4);
			offset = unserializeElement(b, offset, in.h5);
			offset = unserializeElement(b, offset, in.h6);
			offset = unserializeElement(b, offset, in.h7);
			offset = unserializeElement(b, offset, in.h8);
			offset = unserializeElement(b, offset, in.h9);
			offset = unserializeElement(b, offset, in.h10);
			offset = unserializeElement(b, offset, in.gsIDs_org1);
			offset = unserializeElement(b, offset, in.gsIDs_org2);
			offset = unserializeElement(b, offset, in.gsIDs_org3);
			offset = unserializeElement(b, offset, in.gsIDs_org4);
			offset = unserializeElement(b, offset, in.gsIDs_org5);
			offset = unserializeElement(b, offset, in.gsIDs_org6);
			offset = unserializeElement(b, offset, in.gbsIDs_org1);
			offset = unserializeElement(b, offset, in.gbsIDs_org2);
			offset = unserializeElement(b, offset, in.gbsIDs_org3);
			offset = unserializeElement(b, offset, in.gbsIDs_org4);
			offset = unserializeElement(b, offset, in.gbsIDs_org5);
			offset = unserializeElement(b, offset, in.gbsIDs_org6);
			offset = unserializeElement(b, offset, in.sID_org1);
			offset = unserializeElement(b, offset, in.sID_org2);
			offset = unserializeElement(b, offset, in.sID_org3);
			offset = unserializeElement(b, offset, in.sID_org4);
			offset = unserializeElement(b, offset, in.sID_org5);
			offset = unserializeElement(b, offset, in.sID_org6);
			offset = unserializeElement(b, offset, in.sIDr_org1);
			offset = unserializeElement(b, offset, in.sIDr_org2);
			offset = unserializeElement(b, offset, in.sIDr_org3);
			offset = unserializeElement(b, offset, in.sIDr_org4);
			offset = unserializeElement(b, offset, in.sIDr_org5);
			offset = unserializeElement(b, offset, in.sIDr_org6);
			offset = unserializeElement(b, offset, in.hb1);
			offset = unserializeElement(b, offset, in.hb2);
			offset = unserializeElement(b, offset, in.hb3);
			offset = unserializeElement(b, offset, in.hb4);
			offset = unserializeElement(b, offset, in.hb5);
			offset = unserializeElement(b, offset, in.hb6);
			offset = unserializeElement(b, offset, in.hb7);
			offset = unserializeElement(b, offset, in.hb8);
			offset = unserializeElement(b, offset, in.hb9);
			offset = unserializeElement(b, offset, in.hb10);
			offset = unserializeElement(b, offset, in.hbb1);
			offset = unserializeElement(b, offset, in.hbb2);
			offset = unserializeElement(b, offset, in.hbb3);
			offset = unserializeElement(b, offset, in.hbb4);
			offset = unserializeElement(b, offset, in.hbb5);
			offset = unserializeElement(b, offset, in.hbb6);
			offset = unserializeElement(b, offset, in.hbb7);
			offset = unserializeElement(b, offset, in.hbb8);
			offset = unserializeElement(b, offset, in.hbb9);
			offset = unserializeElement(b, offset, in.hbb10);

			pub.Ircpabe_comp.add(in);
		}
		return pub;
	}

	/* Method has been test okay */
	public static byte[] serializeBswabeMsk(BswabeMsk msk) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
	
		serializeElement(arrlist, msk.beta);
		serializeElement(arrlist, msk.g_alpha);

		serializeElement(arrlist, msk.b_new);
		serializeElement(arrlist, msk.s_new);
		serializeElement(arrlist, msk.alpha);

		return Byte_arr2byte_arr(arrlist);
	}

	/* Method has been test okay */
	public static BswabeMsk unserializeBswabeMsk(BswabePub pub, byte[] b) {
		int offset = 0;
		BswabeMsk msk = new BswabeMsk();
	
		msk.beta = pub.p.getZr().newElement();
		msk.g_alpha = pub.p.getG2().newElement();
		msk.b_new = pub.p.getZr().newElement();
		msk.s_new = pub.p.getZr().newElement();
		msk.alpha = pub.p.getGT().newElement();

		offset = unserializeElement(b, offset, msk.beta);
		offset = unserializeElement(b, offset, msk.g_alpha);

		offset = unserializeElement(b, offset, msk.b_new);
		offset = unserializeElement(b, offset, msk.s_new);
		offset = unserializeElement(b, offset, msk.alpha);
		return msk;
	}

	/* Method has been test okay */
	public static byte[] serializeBswabePrv(BswabePrv prv) {
		ArrayList<Byte> arrlist;
		int prvCompsLen, i;
	
		arrlist = new ArrayList<Byte>();
		prvCompsLen = prv.comps.size();
		serializeElement(arrlist, prv.d);
		serializeUint32(arrlist, prvCompsLen);
	
		for (i = 0; i < prvCompsLen; i++) {
			serializeString(arrlist, prv.comps.get(i).attr);
			serializeElement(arrlist, prv.comps.get(i).d);
			serializeElement(arrlist, prv.comps.get(i).dp);
		}
		return Byte_arr2byte_arr(arrlist);
	}

	/* Method has been test okay */
	public static BswabePrv unserializeBswabePrv(BswabePub pub, byte[] b) {
		BswabePrv prv;
		int i, offset, len;
	
		prv = new BswabePrv();
		offset = 0;
	
		prv.d = pub.p.getG2().newElement();
		offset = unserializeElement(b, offset, prv.d);
	
		prv.comps = new ArrayList<BswabePrvComp>();
		len = unserializeUint32(b, offset);
		offset += 4;
	
		for (i = 0; i < len; i++) {
			BswabePrvComp c = new BswabePrvComp();
	
			StringBuffer sb = new StringBuffer("");
			offset = unserializeString(b, offset, sb);
			c.attr = sb.substring(0);
	
			c.d = pub.p.getG2().newElement();
			c.dp = pub.p.getG2().newElement();
	
			offset = unserializeElement(b, offset, c.d);
			offset = unserializeElement(b, offset, c.dp);
	
			prv.comps.add(c);
		}
		return prv;
	}

	public static byte[] serializeIrcpabePrv(BswabePrv prv) {
		ArrayList<Byte> arrlist;
		arrlist = new ArrayList<Byte>();

		int prvCompsLen = prv.comps.size();
		int KaCompsLen = prv.Ka_comps.size();
		int KuCompsLen = prv.Ku_comps.size();
		int HxCompsLen = prv.hx_comps.size();
		int HtCompsLen = prv.ht_comps.size();
		int HbtCompsLen = prv.hbt_comps.size();

		serializeElement(arrlist, prv.d);
		serializeElement(arrlist, prv.K0);
		serializeElement(arrlist, prv.Lu);
		serializeElement(arrlist, prv.La);


		serializeUint32(arrlist, prvCompsLen);

		for (int i = 0; i < prvCompsLen; i++) {
			serializeString(arrlist, prv.comps.get(i).attr);
			serializeElement(arrlist, prv.comps.get(i).d);
			serializeElement(arrlist, prv.comps.get(i).dp);
		}
		for(int i = 0; i < KaCompsLen; i++){
			serializeString(arrlist, prv.Ka_comps.get(i).attr);
			serializeElement(arrlist, prv.Ka_comps.get(i).ele);
		}
		for(int i = 0; i < KuCompsLen; i++){
			serializeString(arrlist, prv.Ku_comps.get(i).attr);
			serializeElement(arrlist, prv.Ku_comps.get(i).ele);
		}
		for(int i = 0; i < HxCompsLen; i++){
			serializeString(arrlist, prv.hx_comps.get(i).attr);
			serializeElement(arrlist, prv.hx_comps.get(i).ele);
		}
		for(int i = 0; i < HtCompsLen; i++){
			serializeString(arrlist, prv.ht_comps.get(i).attr);
			serializeElement(arrlist, prv.ht_comps.get(i).ele);
		}
		for(int i = 0; i < HbtCompsLen; i++){
			serializeString(arrlist, prv.hbt_comps.get(i).attr);
			serializeElement(arrlist, prv.hbt_comps.get(i).ele);
		}
		return Byte_arr2byte_arr(arrlist);
	}

	public static BswabePrv unserializeIrcpabePrv(BswabePub pub, byte[] b){
		BswabePrv prv = new BswabePrv();
		int offset = 0;
		int len;

		prv.d = pub.p.getG2().newElement();
		offset = unserializeElement(b, offset, prv.d);

		prv.Ka_comps = new ArrayList<Ka>();
		prv.Ku_comps = new ArrayList<Ku>();
		prv.hx_comps = new ArrayList<hx>();
		prv.ht_comps = new ArrayList<ht>();
		prv.hbt_comps = new ArrayList<hbt>();

		len = unserializeUint32(b, offset);
		offset += 4;
		for(int i = 0; i< len; i++){
			Ka ka = new Ka();
			Ku ku = new Ku();
			hx hx = new hx();
			hbt htbt = new hbt();
			offset += 4;

			StringBuffer sb = new StringBuffer("");
			offset = unserializeString(b, offset, sb);
			ka.attr = sb.substring(0);
			ka.ele = pub.p.getG2().newElement();
			offset = unserializeElement(b, offset, ka.ele);
		}
		return prv;
	}
	public static byte[] bswabeCphSerialize(BswabeCph cph) {
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
		SerializeUtils.serializeElement(arrlist, cph.cs);
		SerializeUtils.serializeElement(arrlist, cph.c);
		SerializeUtils.serializePolicy(arrlist, cph.p);

		return Byte_arr2byte_arr(arrlist);
	}

	public static BswabeCph bswabeCphUnserialize(BswabePub pub, byte[] cphBuf) {
		BswabeCph cph = new BswabeCph();
		int offset = 0;
		int[] offset_arr = new int[1];

		cph.cs = pub.p.getGT().newElement();
		cph.c = pub.p.getG1().newElement();

		offset = SerializeUtils.unserializeElement(cphBuf, offset, cph.cs);
		offset = SerializeUtils.unserializeElement(cphBuf, offset, cph.c);

		offset_arr[0] = offset;
		cph.p = SerializeUtils.unserializePolicy(pub, cphBuf, offset_arr);
		offset = offset_arr[0];

		return cph;
	}

	/* Method has been test okay */
	/* potential problem: the number to be serialize is less than 2^31 */
	private static void serializeUint32(ArrayList<Byte> arrlist, int k) {
		int i;
		byte b;
	
		for (i = 3; i >= 0; i--) {
			b = (byte) ((k & (0x000000ff << (i * 8))) >> (i * 8));
			arrlist.add(Byte.valueOf(b));
		}
	}

	/*
	 * Usage:
	 * 
	 * You have to do offset+=4 after call this method
	 */
	/* Method has been test okay */
	private static int unserializeUint32(byte[] arr, int offset) {
		int i;
		int r = 0;
	
		for (i = 3; i >= 0; i--)
			r |= (byte2int(arr[offset++])) << (i * 8);
		return r;
	}

	private static void serializePolicy(ArrayList<Byte> arrlist, BswabePolicy p) {
		serializeUint32(arrlist, p.k);
	
		if (p.children == null || p.children.length == 0) {
			serializeUint32(arrlist, 0);
			serializeString(arrlist, p.attr);
			serializeElement(arrlist, p.c);
			serializeElement(arrlist, p.cp);
		} else {
			serializeUint32(arrlist, p.children.length);
			for (int i = 0; i < p.children.length; i++)
				serializePolicy(arrlist, p.children[i]);
		}
	}

	private static BswabePolicy unserializePolicy(BswabePub pub, byte[] arr, int[] offset) {
		int i;
		int n;
		BswabePolicy p = new BswabePolicy();
		p.k = unserializeUint32(arr, offset[0]);
		offset[0] += 4;
		p.attr = null;
	
		/* children */
		n = unserializeUint32(arr, offset[0]);
		offset[0] += 4;
		if (n == 0) {
			p.children = null;
	
			StringBuffer sb = new StringBuffer("");
			offset[0] = unserializeString(arr, offset[0], sb);
			p.attr = sb.substring(0);
	
			p.c = pub.p.getG1().newElement();
			p.cp = pub.p.getG1().newElement();
	
			offset[0] = unserializeElement(arr, offset[0], p.c);
			offset[0] = unserializeElement(arr, offset[0], p.cp);
		} else {
			p.children = new BswabePolicy[n];
			for (i = 0; i < n; i++)
				p.children[i] = unserializePolicy(pub, arr, offset);
		}
	
		return p;
	}

	private static int byte2int(byte b) {
		if (b >= 0)
			return b;
		return (256 + b);
	}

	private static void byteArrListAppend(ArrayList<Byte> arrlist, byte[] b) {
		int len = b.length;
		for (int i = 0; i < len; i++)
			arrlist.add(Byte.valueOf(b[i]));
	}

	private static byte[] Byte_arr2byte_arr(ArrayList<Byte> B) {
		int len = B.size();
		byte[] b = new byte[len];
	
		for (int i = 0; i < len; i++)
			b[i] = B.get(i).byteValue();
	
		return b;
	}

}
