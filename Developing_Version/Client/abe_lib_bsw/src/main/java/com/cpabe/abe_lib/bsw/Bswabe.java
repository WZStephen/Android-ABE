package com.cpabe.abe_lib.bsw;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Bswabe {

	/*
	 * Generate a public key and corresponding master secret key.
	 */
	private static String curveParams = "type a\n"
			+ "q 87807107996633125224377819847540498158068831994142082"
			+ "1102865339926647563088022295707862517942266222142315585"
			+ "8769582317459277713367317481324925129998224791\n"
			+ "h 12016012264891146079388821366740534204802954401251311"
			+ "822919615131047207289359704531102844802183906537786776\n"
			+ "r 730750818665451621361119245571504901405976559617\n"
			+ "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

	public static void setup(BswabePub pub, BswabeMsk msk) {
		Element alpha, beta_inv;
		CurveParameters params = new DefaultCurveParameters().load(new ByteArrayInputStream(curveParams.getBytes()));
		pub.pairingDesc = curveParams;
		pub.p = PairingFactory.getPairing(params);
		Pairing pairing = pub.p;

		pub.g = pairing.getG1().newElement();
		pub.f = pairing.getG1().newElement();
		pub.h = pairing.getG1().newElement();
		pub.gp = pairing.getG2().newElement();
		pub.g_hat_alpha = pairing.getGT().newElement();
		alpha = pairing.getZr().newElement();
		msk.beta = pairing.getZr().newElement();
		msk.g_alpha = pairing.getG2().newElement();

		alpha.setToRandom();
		msk.beta.setToRandom();
		pub.g.setToRandom();
		pub.gp.setToRandom();

		msk.g_alpha = pub.gp.duplicate();
		msk.g_alpha.powZn(alpha);

		beta_inv = msk.beta.duplicate();
		beta_inv.invert();

		pub.f = pub.g.duplicate();
		pub.f.powZn(beta_inv);
		pub.h = pub.g.duplicate();
		pub.h.powZn(msk.beta);
		pub.g_hat_alpha = pairing.pairing(pub.g, msk.g_alpha);
	}

	public static HashMap<String, Element> gsetup(){
		//return global parameters{g1,g2,h}
		CurveParameters params = new DefaultCurveParameters().load(new ByteArrayInputStream(curveParams.getBytes()));
		BswabePub pub = new BswabePub();
		pub.pairingDesc = curveParams;
		pub.p = PairingFactory.getPairing(params);
		Pairing pairing = pub.p;

		Element g1 = pairing.getG1().newRandomElement();
		Element g2 = pairing.getG2().newRandomElement();

		Element h_new_1 = pairing.getG1().newElement().setToRandom();
		Element h_new_2 = pairing.getG1().newElement().setToRandom();
		Element h_new_3 = pairing.getG1().newElement().setToRandom();
		Element h_new_4 = pairing.getG1().newElement().setToRandom();
		Element h_new_5 = pairing.getG1().newElement().setToRandom();
		Element h_new_6 = pairing.getG1().newElement().setToRandom();
		Element h_new_7 = pairing.getG1().newElement().setToRandom();
		Element h_new_8 = pairing.getG1().newElement().setToRandom();
		Element h_new_9 = pairing.getG1().newElement().setToRandom();
		Element h_new_10 = pairing.getG1().newElement().setToRandom();

		HashMap<String, Element> gp = new HashMap<>();
		gp.put("g1", g1);
		gp.put("g2", g2);
		gp.put("h1", h_new_1);
		gp.put("h2", h_new_2);
		gp.put("h3", h_new_3);
		gp.put("h4", h_new_4);
		gp.put("h5", h_new_5);
		gp.put("h6", h_new_6);
		gp.put("h7", h_new_7);
		gp.put("h8", h_new_8);
		gp.put("h9", h_new_9);
		gp.put("h10", h_new_10);

		return gp;
	}

	public static void ta_setup_tree(BswabePub pub, BswabeMsk msk, Node root, HashMap<String, Element> gp) throws NoSuchAlgorithmException {
		Element alpha, beta_inv;
		CurveParameters params = new DefaultCurveParameters().load(new ByteArrayInputStream(curveParams.getBytes()));
		pub.pairingDesc = curveParams;
		pub.p = PairingFactory.getPairing(params);
		Pairing pairing = pub.p;

		pub.g = pairing.getG1().newElement();
		pub.f = pairing.getG1().newElement();
		pub.h = pairing.getG1().newElement();
		pub.gp = pairing.getG2().newElement();
		pub.g_hat_alpha = pairing.getGT().newElement();
		alpha = pairing.getZr().newElement();
		msk.beta = pairing.getZr().newElement();
		msk.g_alpha = pairing.getG2().newElement();

		alpha.setToRandom();
		msk.beta.setToRandom();
		pub.g.setToRandom();
		pub.gp.setToRandom();

		msk.g_alpha = pub.gp.duplicate();
		msk.g_alpha.powZn(alpha);

		beta_inv = msk.beta.duplicate();
		beta_inv.invert();

		pub.f = pub.g.duplicate();
		pub.f.powZn(beta_inv);
		pub.h = pub.g.duplicate();
		pub.h.powZn(msk.beta);
		pub.g_hat_alpha = pairing.pairing(pub.g, msk.g_alpha);

		//---------------integrate key with root node information during keygen---------------------
		alpha = pairing.getGT().newRandomElement();
		Element b = pairing.getZr().newElement().setToRandom().getImmutable();
		Element s = pairing.getZr().newElement().setToRandom().getImmutable();

		//added new pub key structure
		Element ZR = pairing.getZr().newElement();
		String[] all_orgs = new String[]{"org1", "org2", "org3", "org4", "org5", "org6"};

		Element g1 = gp.get("g1").getImmutable();
		Element g1b = g1.powZn(b).getImmutable();
		Element g1bb = g1b.powZn(b);
		Element g2 = gp.get("g2").getImmutable();
		Element g2b = g2.powZn(b).getImmutable();

		Element h1 = gp.get("h1").getImmutable();
		Element h2 = gp.get("h2").getImmutable();
		Element h3 = gp.get("h3").getImmutable();
		Element h4 = gp.get("h4").getImmutable();
		Element h5 = gp.get("h5").getImmutable();
		Element h6 = gp.get("h6").getImmutable();
		Element h7 = gp.get("h7").getImmutable();
		Element h8 = gp.get("h8").getImmutable();
		Element h9 = gp.get("h9").getImmutable();
		Element h10 = gp.get("h10").getImmutable();
		Element g1_alpha = g1.powZn(alpha).getImmutable();

		//new pub key structure
		pub.Ircpabe_comp = new ArrayList<>();
		Ircpabe in = new Ircpabe();
		in.g1 = g1;
		in.g2 = g2;
		in.g2b = g2b;
		in.g1b = g1b;
		in.g1bb = g1bb;
		for(int i = 1; i <= 10; i++){
			String index = "h" + i;
			Insert_Ircpabe(index, gp.get(index), in);
		}

		for(int i = 1; i <= 10; i++){
			String h_index = "h" + i;
			String hb_index = "hb" + i;
			String hbb_index1 = "hbb" + i;

			Element hb_current  =gp.get(h_index).getImmutable().powZn(b);
			Element hbb_current  =gp.get(h_index).getImmutable().powZn(b.mul(b));

			Insert_Ircpabe(hb_index, hb_current, in);
			Insert_Ircpabe(hbb_index1, hbb_current, in);
		}

		in.sID_org1 = elementFromString_rev(root.getValue(), ZR).powZn(s).getImmutable();
		in.sIDr_org1 = in.sID_org1.duplicate().invert().getImmutable();
		in.sID_org2 = elementFromString_rev(all_orgs[1], pairing.getZr().newElement()).powZn(in.sID_org1).getImmutable();
		in.sIDr_org2 = in.sID_org2.duplicate().invert().getImmutable();
		in.sID_org3 = elementFromString_rev(all_orgs[2], pairing.getZr().newElement()).powZn(in.sID_org1).getImmutable();
		in.sIDr_org3 = in.sID_org3.duplicate().invert().getImmutable();
		in.sID_org4 = elementFromString_rev(all_orgs[3], pairing.getZr().newElement()).powZn(in.sID_org1).getImmutable();
		in.sIDr_org4 = in.sID_org4.duplicate().invert().getImmutable();
		in.sID_org5 = elementFromString_rev(all_orgs[4], pairing.getZr().newElement()).powZn(in.sID_org2).getImmutable();
		in.sIDr_org5 = in.sID_org5.duplicate().invert().getImmutable();
		in.sID_org6 = elementFromString_rev(all_orgs[5], pairing.getZr().newElement()).powZn(in.sID_org2).getImmutable();
		in.sIDr_org6 = in.sID_org6.duplicate().invert().getImmutable();

		for(int i = 1; i <= 6; i++){
			String gsIDs_index = "gsIDs_org"+i;
			String gbsIDs_index = "gbsIDs_org" + i;

			Element sIDr_current = Get_Ircpabe("sIDr_org"+i, in);

			Insert_Ircpabe(gsIDs_index, g2.powZn(sIDr_current), in);
			Insert_Ircpabe(gbsIDs_index, g2b.powZn(sIDr_current), in);
		}
		in.e_gg_alpha = pairing.pairing(g1_alpha, g2);

		pub.Ircpabe_comp.add(in);

		//new msk key structure
		msk.s_new = s;
		msk.b_new = b;
		msk.alpha = g1.powZn(alpha);
	}

	public static void federated_setup1(BswabePub pub1, BswabePub pub2,BswabeMsk msk2, Node root, HashMap<String, Element> gp) throws NoSuchAlgorithmException {
		CurveParameters params = new DefaultCurveParameters().load(new ByteArrayInputStream(curveParams.getBytes()));
		pub1.pairingDesc = curveParams;
		pub1.p = PairingFactory.getPairing(params);
		Pairing pairing = pub1.p;

		Element ZR = pairing.getZr().newElement();

		String[] all_orgs = new String[]{"org1", "org2", "org3", "org4", "org5", "org6"};
		Element b = msk2.b_new;
		Element alpha = msk2.alpha;
		Element s = msk2.s_new;

		Element g2b = pub1.Ircpabe_comp.get(0).g2b.powZn(b);
		Element g1b = pub1.Ircpabe_comp.get(0).g1b.powZn(b);
		Element g1bb = pub1.Ircpabe_comp.get(0).g1bb.powZn(b);
		Element e_gg_alpha = pub1.Ircpabe_comp.get(0).e_gg_alpha.mul(pairing.pairing(gp.get("g1"), gp.get("g2")).powZn(alpha));

		Element hb1 = pub1.Ircpabe_comp.get(0).hb1.powZn(b);
		Element hbb1 = pub1.Ircpabe_comp.get(0).hbb1.powZn(b.mul(b));
		Element hb2 = pub1.Ircpabe_comp.get(0).hb2.powZn(b);
		Element hbb2 = pub1.Ircpabe_comp.get(0).hbb2.powZn(b.mul(b));
		Element hb3 = pub1.Ircpabe_comp.get(0).hb3.powZn(b);
		Element hbb3 = pub1.Ircpabe_comp.get(0).hbb3.powZn(b.mul(b));
		Element hb4 = pub1.Ircpabe_comp.get(0).hb4.powZn(b);
		Element hbb4 = pub1.Ircpabe_comp.get(0).hbb4.powZn(b.mul(b));
		Element hb5 = pub1.Ircpabe_comp.get(0).hb5.powZn(b);
		Element hbb5 = pub1.Ircpabe_comp.get(0).hbb5.powZn(b.mul(b));
		Element hb6 = pub1.Ircpabe_comp.get(0).hb6.powZn(b);
		Element hbb6 = pub1.Ircpabe_comp.get(0).hbb6.powZn(b.mul(b));
		Element hb7 = pub1.Ircpabe_comp.get(0).hb7.powZn(b);
		Element hbb7 = pub1.Ircpabe_comp.get(0).hbb7.powZn(b.mul(b));
		Element hb8 = pub1.Ircpabe_comp.get(0).hb8.powZn(b);
		Element hbb8 = pub1.Ircpabe_comp.get(0).hbb8.powZn(b.mul(b));
		Element hb9 = pub1.Ircpabe_comp.get(0).hb9.powZn(b);
		Element hbb9 = pub1.Ircpabe_comp.get(0).hbb9.powZn(b.mul(b));
		Element hb10 = pub1.Ircpabe_comp.get(0).hb10.powZn(b);
		Element hbb10 = pub1.Ircpabe_comp.get(0).hbb10.powZn(b.mul(b));

		Element sID_org1 = pub1.Ircpabe_comp.get(0).sID_org1.mul(elementFromString_rev(root.getValue(), ZR).powZn(s).getImmutable());
		Element sIDr_org1 = sID_org1.invert();
		Element sID_org2 = pub1.Ircpabe_comp.get(0).sID_org2.mul(elementFromString_rev(root.getValue(), ZR).powZn(sID_org1).getImmutable());
		Element sIDr_org2 = sID_org2.invert();
		Element sID_org3 = pub1.Ircpabe_comp.get(0).sID_org3.mul(elementFromString_rev(root.getValue(), ZR).powZn(sID_org1).getImmutable());
		Element sIDr_org3 = sID_org3.invert();
		Element sID_org4 = pub1.Ircpabe_comp.get(0).sID_org4.mul(elementFromString_rev(root.getValue(), ZR).powZn(sID_org1).getImmutable());
		Element sIDr_org4 = sID_org4.invert();
		Element sID_org5 = pub1.Ircpabe_comp.get(0).sID_org5.mul(elementFromString_rev(root.getValue(), ZR).powZn(sID_org2).getImmutable());
		Element sIDr_org5 = sID_org5.invert();
		Element sID_org6 = pub1.Ircpabe_comp.get(0).sID_org6.mul(elementFromString_rev(root.getValue(), ZR).powZn(sID_org2).getImmutable());
		Element sIDr_org6 = sID_org6.invert();

		Element gsIDs_org1 = pub1.Ircpabe_comp.get(0).g2.powZn(sIDr_org1);
		Element gbsIDs_org1 = pub1.Ircpabe_comp.get(0).g2b.powZn(sIDr_org1);
		Element gsIDs_org2 = pub1.Ircpabe_comp.get(0).g2.powZn(sIDr_org2);
		Element gbsIDs_org2 = pub1.Ircpabe_comp.get(0).g2b.powZn(sIDr_org2);
		Element gsIDs_org3 = pub1.Ircpabe_comp.get(0).g2.powZn(sIDr_org3);
		Element gbsIDs_org3 = pub1.Ircpabe_comp.get(0).g2b.powZn(sIDr_org3);
		Element gsIDs_org4 = pub1.Ircpabe_comp.get(0).g2.powZn(sIDr_org4);
		Element gbsIDs_org4 = pub1.Ircpabe_comp.get(0).g2b.powZn(sIDr_org4);
		Element gsIDs_org5 = pub1.Ircpabe_comp.get(0).g2.powZn(sIDr_org5);
		Element gbsIDs_org5 = pub1.Ircpabe_comp.get(0).g2b.powZn(sIDr_org5);
		Element gsIDs_org6 = pub1.Ircpabe_comp.get(0).g2.powZn(sIDr_org6);
		Element gbsIDs_org6 = pub1.Ircpabe_comp.get(0).g2b.powZn(sIDr_org6);

		//federated public keygen
		pub2.Ircpabe_comp = new ArrayList<>();
		Ircpabe in_pub2 = new Ircpabe();
		in_pub2.g1 = pub1.Ircpabe_comp.get(0).g1;
		in_pub2.g2 = pub1.Ircpabe_comp.get(0).g2;
		in_pub2.g2b = g2b;
		in_pub2.g1b = g1b;
		in_pub2.g1bb = g1bb;

		in_pub2.e_gg_alpha = e_gg_alpha;
		for(int i = 1; i <= 10; i++){
			String h_index = "h" + i;
			Element pub1_h_index = Get_Ircpabe(h_index, pub1.Ircpabe_comp.get(0));
			Insert_Ircpabe(h_index, pub1_h_index, in_pub2);
		}

		in_pub2.hb1 = hb1;
		in_pub2.hb2 = hb2;
		in_pub2.hb3 = hb3;
		in_pub2.hb4 = hb4;
		in_pub2.hb5 = hb5;
		in_pub2.hb6 = hb6;
		in_pub2.hb7 = hb7;
		in_pub2.hb8 = hb8;
		in_pub2.hb9 = hb9;
		in_pub2.hb10 = hb10;
		in_pub2.hbb1 = hbb1;
		in_pub2.hbb2 = hbb2;
		in_pub2.hbb3 = hbb3;
		in_pub2.hbb4 = hbb4;
		in_pub2.hbb5 = hbb5;
		in_pub2.hbb6 = hbb6;
		in_pub2.hbb7 = hbb7;
		in_pub2.hbb8 = hbb8;
		in_pub2.hbb9 = hbb9;
		in_pub2.hbb10 = hbb10;
		in_pub2.gsIDs_org1 = gsIDs_org1;
		in_pub2.gsIDs_org2 = gsIDs_org2;
		in_pub2.gsIDs_org3 = gsIDs_org3;
		in_pub2.gsIDs_org4 = gsIDs_org4;
		in_pub2.gsIDs_org5 = gsIDs_org5;
		in_pub2.gsIDs_org6 = gsIDs_org6;
		in_pub2.gbsIDs_org1 = gbsIDs_org1;
		in_pub2.gbsIDs_org2 = gbsIDs_org2;
		in_pub2.gbsIDs_org3 = gbsIDs_org3;
		in_pub2.gbsIDs_org4 = gbsIDs_org4;
		in_pub2.gbsIDs_org5 = gbsIDs_org5;
		in_pub2.gbsIDs_org6 = gbsIDs_org6;
		in_pub2.sID_org1 = sID_org1;
		in_pub2.sID_org2 = sID_org2;
		in_pub2.sID_org3 = sID_org3;
		in_pub2.sID_org4 = sID_org4;
		in_pub2.sID_org5 = sID_org5;
		in_pub2.sID_org6 = sID_org6;
		in_pub2.sIDr_org1 = sIDr_org1;
		in_pub2.sIDr_org2 = sIDr_org2;
		in_pub2.sIDr_org3 = sIDr_org3;
		in_pub2.sIDr_org4 = sIDr_org4;
		in_pub2.sIDr_org5 = sIDr_org5;
		in_pub2.sIDr_org6 = sIDr_org6;

		pub2.Ircpabe_comp.add(in_pub2);
	}

	public static void org_keygen(String[] attr_assigned, Node root, BswabeMsk msk,BswabePub pub, BswabePrv prv, HashMap<String, Element> gp) throws NoSuchAlgorithmException {
		CurveParameters params = new DefaultCurveParameters().load(new ByteArrayInputStream(curveParams.getBytes()));
		pub.pairingDesc = curveParams;
		pub.p = PairingFactory.getPairing(params);
		Pairing pairing = pub.p;

		Element alpha = msk.alpha;
		Element g1 = pub.Ircpabe_comp.get(0).g1.getImmutable();
		Element g1b = pub.Ircpabe_comp.get(0).g1b.getImmutable();
		Element g2 = pub.Ircpabe_comp.get(0).g2.getImmutable();
		Element g2b = pub.Ircpabe_comp.get(0).g2b.getImmutable();
		Element g1bb = pub.Ircpabe_comp.get(0).g1bb.getImmutable();
		Element h1 = pub.Ircpabe_comp.get(0).h1.getImmutable();
		Element h2 = pub.Ircpabe_comp.get(0).h2.getImmutable();
		Element h3 = pub.Ircpabe_comp.get(0).h3.getImmutable();
		Element h4 = pub.Ircpabe_comp.get(0).h4.getImmutable();
		Element h5 = pub.Ircpabe_comp.get(0).h5.getImmutable();
		Element h6 = pub.Ircpabe_comp.get(0).h6.getImmutable();
		Element h7 = pub.Ircpabe_comp.get(0).h7.getImmutable();
		Element h8 = pub.Ircpabe_comp.get(0).h8.getImmutable();
		Element h9 = pub.Ircpabe_comp.get(0).h9.getImmutable();
		Element h10 = pub.Ircpabe_comp.get(0).h10.getImmutable();
		Element hb1 = pub.Ircpabe_comp.get(0).hb1.getImmutable();
		Element hb2 = pub.Ircpabe_comp.get(0).hb2.getImmutable();
		Element hb3 = pub.Ircpabe_comp.get(0).hb3.getImmutable();
		Element hb4 = pub.Ircpabe_comp.get(0).hb4.getImmutable();
		Element hb5 = pub.Ircpabe_comp.get(0).hb5.getImmutable();
		Element hb6 = pub.Ircpabe_comp.get(0).hb6.getImmutable();
		Element hb7 = pub.Ircpabe_comp.get(0).hb7.getImmutable();
		Element hb8 = pub.Ircpabe_comp.get(0).hb8.getImmutable();
		Element hb9 = pub.Ircpabe_comp.get(0).hb9.getImmutable();
		Element hb10 = pub.Ircpabe_comp.get(0).hb10.getImmutable();
		Element gbsIDs_org1 = pub.Ircpabe_comp.get(0).gbsIDs_org1;
		Element gbsIDs_org2 = pub.Ircpabe_comp.get(0).gbsIDs_org2;
		Element gbsIDs_org3 = pub.Ircpabe_comp.get(0).gbsIDs_org3;
		Element gbsIDs_org4 = pub.Ircpabe_comp.get(0).gbsIDs_org4;
		Element gbsIDs_org5 = pub.Ircpabe_comp.get(0).gbsIDs_org5;
		Element gbsIDs_org6 = pub.Ircpabe_comp.get(0).gbsIDs_org6;
		Element gsIDs_org1 = pub.Ircpabe_comp.get(0).gsIDs_org1;
		Element gsIDs_org2 = pub.Ircpabe_comp.get(0).gsIDs_org2;
		Element gsIDs_org3 = pub.Ircpabe_comp.get(0).gsIDs_org3;
		Element gsIDs_org4 = pub.Ircpabe_comp.get(0).gsIDs_org4;
		Element gsIDs_org5 = pub.Ircpabe_comp.get(0).gsIDs_org5;
		Element gsIDs_org6 = pub.Ircpabe_comp.get(0).gsIDs_org6;

		Element t = pairing.getZr().newRandomElement().getImmutable();
		Element sID = pub.Ircpabe_comp.get(0).sID_org1.getImmutable();
		Element sIDr = sID.invert().getImmutable();

		Element K0 = (g1.powZn(alpha)).mul(g1bb.powZn(t));

		Element Lu = (g2.powZn(t)).invert();
		Element La = (g2.powZn(sIDr.mul(t)));

		Element gbsID = g1b.powZn(sID);
		Element gbt = g1b.powZn(t);

		prv.Ka_comps = new ArrayList<>();
		prv.Kastr_comps = new ArrayList<>();
		prv.Ku_comps = new ArrayList<>();
		prv.Kustr_comps = new ArrayList<>();
		prv.hx_comps = new ArrayList<>();
		prv.hstr_comps = new ArrayList<>();
		prv.ht_comps = new ArrayList<>();
		prv.htstr_comps = new ArrayList<>();
		prv.hbt_comps = new ArrayList<>();
		prv.hbtstr_comps = new ArrayList<>();

		Ka ka = new Ka();
		Kastr kastr = new Kastr();
		Ku ku = new Ku();
		Kustr kustr = new Kustr();
		hx hx = new hx();
		hxstr hstr = new hxstr();
		ht ht = new ht();
		htstr htstr = new htstr();
		hbt hbt = new hbt();
		hbtstr hbtstr = new hbtstr();

		int len = attr_assigned.length;
		for(int i=0; i<len; i++){
			//10 attribute parameters
			Ka ka_comp = new Ka();
			Ku ku_comp = new Ku();
			hx hx_comp = new hx();
			ht ht_comp = new ht();
			hbt hbt_comp = new hbt();

			ka_comp.attr = attr_assigned[i];
			ku_comp.attr = attr_assigned[i];
			hx_comp.attr = attr_assigned[i];
			ht_comp.attr = attr_assigned[i];
			hbt_comp.attr = attr_assigned[i];

			switch (i){
				case 0:
					ka_comp.ele = g1b.powZn(sID).mul(hb1).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h1)).powZn(t);
					hx_comp.ele = h1;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb1.powZn(t);
					break;
				case 1:
					ka_comp.ele = g1b.powZn(sID).mul(hb2).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h2)).powZn(t);
					hx_comp.ele = h2;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb2.powZn(t);
					break;
				case 2:
					ka_comp.ele = g1b.powZn(sID).mul(hb3).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h3)).powZn(t);
					hx_comp.ele = h3;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb3.powZn(t);
					break;
				case 3:
					ka_comp.ele = g1b.powZn(sID).mul(hb4).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h4)).powZn(t);
					hx_comp.ele = h4;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb4.powZn(t);
					break;
				case 4:
					ka_comp.ele = g1b.powZn(sID).mul(hb5).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h5)).powZn(t);
					hx_comp.ele = h5;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb5.powZn(t);
					break;
				case 5:
					ka_comp.ele = g1b.powZn(sID).mul(hb6).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h6)).powZn(t);
					hx_comp.ele = h6;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb6.powZn(t);
					break;
				case 6:
					ka_comp.ele = g1b.powZn(sID).mul(hb7).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h7)).powZn(t);
					hx_comp.ele = h7;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb7.powZn(t);
					break;
				case 7:
					ka_comp.ele = g1b.powZn(sID).mul(hb8).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h8)).powZn(t);
					hx_comp.ele = h8;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb8.powZn(t);
					break;
				case 8:
					ka_comp.ele = g1b.powZn(sID).mul(hb9).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h9)).powZn(t);
					hx_comp.ele = h9;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb9.powZn(t);
					break;
				case 9:
					ka_comp.ele = g1b.powZn(sID).mul(hb10).powZn(t);
					ku_comp.ele = ((g1b.powZn(elementFromString_rev("org1", pairing.getZr().newRandomElement()))).mul(h10)).powZn(t);
					hx_comp.ele = h10;
					ht_comp.ele = hx_comp.ele.powZn(t);
					hbt_comp.ele = hb10.powZn(t);
					break;
				default:
					break;
			}
			prv.Ka_comps.add(ka_comp);
			prv.Ku_comps.add(ku_comp);
			prv.hx_comps.add(hx_comp);
			prv.ht_comps.add(ht_comp);
			prv.hbt_comps.add(hbt_comp);
		}
		prv.K0 = K0;
		prv.Lu = Lu;
		prv.La = La;
		prv.sID = sID;
		prv.gbsID = gbsID;
		prv.gbt = gbt;
		prv.ID = "org1";
		prv.org_id = "org1";
	}

	public static void federated_org_keygen(String ID, String attr_list, BswabeMsk ta_msk_file_second, BswabePub pk_file, BswabePrv ta_sk_file_first, BswabePrv ta_sk_file_second, String org_id){

	}

	/*
	 * Generate a private key with the given set of attributes.
	 */
	public static BswabePrv keygen(BswabePub pub, BswabeMsk msk, String[] attrs) throws NoSuchAlgorithmException {
		BswabePrv prv = new BswabePrv();
		Element g_r, r, beta_inv;
		Pairing pairing;

		/* initialize */
		pairing = pub.p;
		prv.d = pairing.getG2().newElement();
		//g_r = pairing.getG2().newElement();
		r = pairing.getZr().newElement();
		//beta_inv = pairing.getZr().newElement();

		//pub.gsIDs = gsIDs;

		/* compute */
		r.setToRandom();
		g_r = pub.gp.duplicate();
		g_r.powZn(r);

		prv.d = msk.g_alpha.duplicate();
		prv.d.mul(g_r);

		beta_inv = msk.beta.duplicate();
		beta_inv.invert();

		prv.d.powZn(beta_inv);

		int len = attrs.length;
		prv.comps = new ArrayList<BswabePrvComp>();
		for (int i = 0; i < len; i++) {
			BswabePrvComp comp = new BswabePrvComp();
			Element h_rp;
			Element rp;

			comp.attr = attrs[i];

			comp.d = pairing.getG2().newElement();
			comp.dp = pairing.getG1().newElement();
			h_rp = pairing.getG2().newElement();
			rp = pairing.getZr().newElement();

			elementFromString(h_rp, comp.attr);
			rp.setToRandom();

			h_rp.powZn(rp);

			comp.d = g_r.duplicate();
			comp.d.mul(h_rp);
			comp.dp = pub.g.duplicate();
			comp.dp.powZn(rp);

			prv.comps.add(comp);
		}
		return prv;
	}

    /*
     * Delegate a subset of attribute of an existing private key.
     */
    public static BswabePrv delegate(BswabePub pub, BswabePrv prv_src, String[] attrs_subset) throws NoSuchAlgorithmException, IllegalArgumentException {

            BswabePrv prv = new BswabePrv();
            Element g_rt, rt, f_at_rt;
            Pairing pairing;

            /* initialize */
            pairing = pub.p;
            prv.d = pairing.getG2().newElement();

            //g_rt = pairing.getG2().newElement();
            rt = pairing.getZr().newElement();
            //f_at_rt = pairing.getZr().newElement();

            /* compute */
            rt.setToRandom();
            f_at_rt = pub.f.duplicate();

            f_at_rt.powZn(rt);
            prv.d = prv_src.d.duplicate();
            prv.d.mul(f_at_rt);

            g_rt = pub.g.duplicate();
            g_rt.powZn(rt);

            int i, len = attrs_subset.length;
            prv.comps = new ArrayList<BswabePrvComp>();

            for (i = 0; i < len; i++) {
                BswabePrvComp comp = new BswabePrvComp();
                Element h_rtp;
                Element rtp;

                comp.attr = attrs_subset[i];

                BswabePrvComp comp_src = new BswabePrvComp();
                boolean comp_src_init = false;

                for (int j = 0; j < prv_src.comps.size(); ++j) {
                    if (prv_src.comps.get(j).attr.equals(comp.attr) ) {
                        comp_src = prv_src.comps.get(j);
                        comp_src_init = true;
                        break;
                    }
                }

                if (comp_src_init == false) {
                    throw new IllegalArgumentException("comp_src_init == false");
                }

                comp.d = pairing.getG2().newElement();
                comp.dp = pairing.getG1().newElement();
                h_rtp = pairing.getG2().newElement();
                rtp = pairing.getZr().newElement();

                elementFromString(h_rtp, comp.attr);
                rtp.setToRandom();

                h_rtp.powZn(rtp);

                comp.d = g_rt.duplicate();
                comp.d.mul(h_rtp);
                comp.d.mul(comp_src.d);

                comp.dp = pub.g.duplicate();
                comp.dp.powZn(rtp); 
                comp.dp.mul(comp_src.dp);
                

                prv.comps.add(comp);
            }

            return prv;
        }
    
	/*
	 * Pick a random group element and encrypt it under the specified access
	 * policy. The resulting ciphertext is returned and the Element given as an
	 * argument (which need not be initialized) is set to the random group
	 * element.
	 * 
	 * After using this function, it is normal to extract the random data in m
	 * using the pbc functions element_length_in_bytes and element_to_bytes and
	 * use it as a key for hybrid encryption.
	 * 
	 * The policy is specified as a simple string which encodes a postorder
	 * traversal of threshold tree defining the access policy. As an example,
	 * 
	 * "foo bar fim 2of3 baf 1of2"
	 * 
	 * specifies a policy with two threshold gates and four leaves. It is not
	 * possible to specify an attribute with whitespace in it (although "_" is
	 * allowed).
	 * 
	 * Numerical attributes and any other fancy stuff are not supported.
	 * 
	 * Returns null if an error occured, in which case a description can be
	 * retrieved by calling bswabe_error().
	 */
	public static BswabeCphKey enc(BswabePub pub, String policy) throws Exception {
		BswabeCphKey keyCph = new BswabeCphKey();
		BswabeCph cph = new BswabeCph();
		Element s, m;

		/* initialize */

		Pairing pairing = pub.p;
		s = pairing.getZr().newElement();
		m = pairing.getGT().newElement();
		cph.cs = pairing.getGT().newElement();
		cph.c = pairing.getG1().newElement();
		cph.p = parsePolicyPostfix(policy);

		/* compute */
		m.setToRandom();
		s.setToRandom();
		cph.cs = pub.g_hat_alpha.duplicate();
		cph.cs.powZn(s); /* num_exps++; */
		cph.cs.mul(m); /* num_muls++; */

		cph.c = pub.h.duplicate();
		cph.c.powZn(s); /* num_exps++; */

		fillPolicy(cph.p, pub, s);

		keyCph.cph = cph;
		keyCph.key = m;

		return keyCph;
	}

	/*
	 * Decrypt the specified ciphertext using the given private key, filling in
	 * the provided element m (which need not be initialized) with the result.
	 * 
	 * Returns true if decryption succeeded, false if this key does not satisfy
	 * the policy of the ciphertext (in which case m is unaltered).
	 */
	public static BswabeElementBoolean dec(BswabePub pub, BswabePrv prv, BswabeCph cph) {
		Element t;
		Element m;
		BswabeElementBoolean beb = new BswabeElementBoolean();

		m = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();

		checkSatisfy(cph.p, prv);
		if (!cph.p.satisfiable) {
			System.err
					.println("cannot decrypt, attributes in key do not satisfy policy");
			beb.e = null;
			beb.b = false;
			return beb;
		}

		pickSatisfyMinLeaves(cph.p, prv);

		decFlatten(t, cph.p, prv, pub);

		m = cph.cs.duplicate();
		m.mul(t); /* num_muls++; */

		t = pub.p.pairing(cph.c, prv.d);
		t.invert();
		m.mul(t); /* num_muls++; */

		beb.e = m;
		beb.b = true;

		return beb;
	}

	private static void decFlatten(Element r, BswabePolicy p, BswabePrv prv, BswabePub pub) {
		Element one;
		one = pub.p.getZr().newElement();
		one.setToOne();
		r.setToOne();

		decNodeFlatten(r, one, p, prv, pub);
	}

	private static void decNodeFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
		if (p.children == null || p.children.length == 0)
			decLeafFlatten(r, exp, p, prv, pub);
		else
			decInternalFlatten(r, exp, p, prv, pub);
	}

	private static void decLeafFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
		BswabePrvComp c;
		Element s, t;

		c = prv.comps.get(p.attri);

		s = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();

		s = pub.p.pairing(p.c, c.d); /* num_pairings++; */
		t = pub.p.pairing(p.cp, c.dp); /* num_pairings++; */
		t.invert();
		s.mul(t); /* num_muls++; */
		s.powZn(exp); /* num_exps++; */

		r.mul(s); /* num_muls++; */
	}

	private static void decInternalFlatten(Element r, Element exp, BswabePolicy p, BswabePrv prv, BswabePub pub) {
		int i;
		Element t, expnew;

		t = pub.p.getZr().newElement();
		expnew = pub.p.getZr().newElement();

		for (i = 0; i < p.satl.size(); i++) {
			lagrangeCoef(t, p.satl, (p.satl.get(i)).intValue());
			expnew = exp.duplicate();
			expnew.mul(t);
			decNodeFlatten(r, expnew, p.children[p.satl.get(i) - 1], prv, pub);
		}
	}

	private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
		int j, k;
		Element t;

		t = r.duplicate();

		r.setToOne();
		for (k = 0; k < s.size(); k++) {
			j = s.get(k).intValue();
			if (j == i)
				continue;
			t.set(-j);
			r.mul(t); /* num_muls++; */
			t.set(i - j);
			t.invert();
			r.mul(t); /* num_muls++; */
		}
	}

	private static void pickSatisfyMinLeaves(BswabePolicy p, BswabePrv prv) {
		int i, k, l, c_i;
		int len;
		ArrayList<Integer> c = new ArrayList<Integer>();

		if (p.children == null || p.children.length == 0)
			p.min_leaves = 1;
		else {
			len = p.children.length;
			for (i = 0; i < len; i++)
				if (p.children[i].satisfiable)
					pickSatisfyMinLeaves(p.children[i], prv);

			for (i = 0; i < len; i++)
				c.add(new Integer(i));

			Collections.sort(c, new IntegerComparator(p));

			p.satl = new ArrayList<Integer>();
			p.min_leaves = 0;
			l = 0;

			for (i = 0; i < len && l < p.k; i++) {
				c_i = c.get(i).intValue(); /* c[i] */
				if (p.children[c_i].satisfiable) {
					l++;
					p.min_leaves += p.children[c_i].min_leaves;
					k = c_i + 1;
					p.satl.add(new Integer(k));
				}
			}
		}
	}

	private static void checkSatisfy(BswabePolicy p, BswabePrv prv) {
		int i, l;
		String prvAttr;

		p.satisfiable = false;
		if (p.children == null || p.children.length == 0) {
			for (i = 0; i < prv.comps.size(); i++) {
				prvAttr = prv.comps.get(i).attr;
				// System.out.println("prvAtt:" + prvAttr);
				// System.out.println("p.attr" + p.attr);
				if (prvAttr.compareTo(p.attr) == 0) {
					// System.out.println("=staisfy=");
					p.satisfiable = true;
					p.attri = i;
					break;
				}
			}
		} else {
			for (i = 0; i < p.children.length; i++)
				checkSatisfy(p.children[i], prv);

			l = 0;
			for (i = 0; i < p.children.length; i++)
				if (p.children[i].satisfiable)
					l++;

			if (l >= p.k)
				p.satisfiable = true;
		}
	}

	private static void fillPolicy(BswabePolicy p, BswabePub pub, Element e) throws NoSuchAlgorithmException {
		int i;
		Element r, t, h;
		Pairing pairing = pub.p;
		r = pairing.getZr().newElement();
		t = pairing.getZr().newElement();
		h = pairing.getG2().newElement();

		p.q = randPoly(p.k - 1, e);

		if (p.children == null || p.children.length == 0) {
			p.c = pairing.getG1().newElement();
			p.cp = pairing.getG2().newElement();

			elementFromString(h, p.attr);
			p.c = pub.g.duplicate();;
			p.c.powZn(p.q.coef[0]); 	
			p.cp = h.duplicate();
			p.cp.powZn(p.q.coef[0]);
		} else {
			for (i = 0; i < p.children.length; i++) {
				r.set(i + 1);
				evalPoly(t, p.q, r);
				fillPolicy(p.children[i], pub, t);
			}
		}

	}

	private static void evalPoly(Element r, BswabePolynomial q, Element x) {
		int i;
		Element s, t;

		s = r.duplicate();
		t = r.duplicate();

		r.setToZero();
		t.setToOne();

		for (i = 0; i < q.deg + 1; i++) {
			/* r += q->coef[i] * t */
			s = q.coef[i].duplicate();
			s.mul(t); 
			r.add(s);

			/* t *= x */
			t.mul(x);
		}

	}

	private static BswabePolynomial randPoly(int deg, Element zeroVal) {
		int i;
		BswabePolynomial q = new BswabePolynomial();
		q.deg = deg;
		q.coef = new Element[deg + 1];

		for (i = 0; i < deg + 1; i++)
			q.coef[i] = zeroVal.duplicate();

		q.coef[0].set(zeroVal);

		for (i = 1; i < deg + 1; i++)
			q.coef[i].setToRandom();

		return q;
	}

	private static BswabePolicy parsePolicyPostfix(String s) throws Exception {
		String[] toks;
		String tok;
		ArrayList<BswabePolicy> stack = new ArrayList<BswabePolicy>();
		BswabePolicy root;

		toks = s.split(" ");

		int toks_cnt = toks.length;
		for (int index = 0; index < toks_cnt; index++) {
			int i, k, n;

			tok = toks[index];
			if (!tok.contains("of")) {
				stack.add(baseNode(1, tok));
			} else {
				BswabePolicy node;

				/* parse kof n node */
				String[] k_n = tok.split("of");
				k = Integer.parseInt(k_n[0]);
				n = Integer.parseInt(k_n[1]);

				if (k < 1) {
					System.out.println("error parsing " + s
							+ ": trivially satisfied operator " + tok);
					return null;
				} else if (k > n) {
					System.out.println("error parsing " + s
							+ ": unsatisfiable operator " + tok);
					return null;
				} else if (n == 1) {
					System.out.println("error parsing " + s
							+ ": indentity operator " + tok);
					return null;
				} else if (n > stack.size()) {
					System.out.println("error parsing " + s
							+ ": stack underflow at " + tok);
					return null;
				}

				/* pop n things and fill in children */
				node = baseNode(k, null);
				node.children = new BswabePolicy[n];

				for (i = n - 1; i >= 0; i--)
					node.children[i] = stack.remove(stack.size() - 1);

				/* push result */
				stack.add(node);
			}
		}

		if (stack.size() > 1) {
			System.out.println("error parsing " + s
					+ ": extra node left on the stack");
			return null;
		} else if (stack.size() < 1) {
			System.out.println("error parsing " + s + ": empty policy");
			return null;
		}

		root = stack.get(0);
		return root;
	}

	private static BswabePolicy baseNode(int k, String s) {
		BswabePolicy p = new BswabePolicy();

		p.k = k;
		if (!(s == null))
			p.attr = s;
		else
			p.attr = null;
		p.q = null;

		return p;
	}

	private static void elementFromString(Element h, String s) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
	}

	private static Element elementFromString_rev(String s, Element h) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
		return h;
	}

	private static class IntegerComparator implements Comparator<Integer> {
		BswabePolicy policy;

		public IntegerComparator(BswabePolicy p) {
			this.policy = p;
		}

		@Override
		public int compare(Integer o1, Integer o2) {
			int k, l;

			k = policy.children[o1.intValue()].min_leaves;
			l = policy.children[o2.intValue()].min_leaves;

			return	k < l ? -1 : 
					k == l ? 0 : 1;
		}
	}

	public static void Insert_Ircpabe(String index, Element ele, Ircpabe obj){
		switch (index) {
			case "g1":
				obj.g1 = ele;
				break;
			case "g1b":
				obj.g1b = ele;
				break;
			case "g1bb":
				obj.g1bb = ele;
				break;
			case "g2":
				obj.g2 = ele;
				break;
			case "g2b":
				obj.g2b = ele;
				break;
			case "e_gg_alpha":
				obj.e_gg_alpha = ele;
				break;
			case "h1":
				obj.h1 = ele;
				break;
			case "h2":
				obj.h2 = ele;
				break;
			case "h3":
				obj.h3 = ele;
				break;
			case "h4":
				obj.h4 = ele;
				break;
			case "h5":
				obj.h5 = ele;
				break;
			case "h6":
				obj.h6 = ele;
				break;
			case "h7":
				obj.h7 = ele;
				break;
			case "h8":
				obj.h8 = ele;
				break;
			case "h9":
				obj.h9 = ele;
				break;
			case "h10":
				obj.h10 = ele;
				break;
			case "gsIDs_org1":
				obj.gsIDs_org1 = ele;
				break;
			case "gsIDs_org2":
				obj.gsIDs_org2 = ele;
				break;
			case "gsIDs_org3":
				obj.gsIDs_org3 = ele;
				break;
			case "gsIDs_org4":
				obj.gsIDs_org4 = ele;
				break;
			case "gsIDs_org5":
				obj.gsIDs_org5 = ele;
				break;
			case "gsIDs_org6":
				obj.gsIDs_org6 = ele;
				break;
			case "gbsIDs_org1":
				obj.gbsIDs_org1 = ele;
				break;
			case "gbsIDs_org2":
				obj.gbsIDs_org2 = ele;
				break;
			case "gbsIDs_org3":
				obj.gbsIDs_org3 = ele;
				break;
			case "gbsIDs_org4":
				obj.gbsIDs_org4 = ele;
				break;
			case "gbsIDs_org5":
				obj.gbsIDs_org5 = ele;
				break;
			case "gbsIDs_org6":
				obj.gbsIDs_org6 = ele;
				break;
			case "sID_org1":
				obj.sID_org1 = ele;
				break;
			case "sID_org2":
				obj.sID_org2 = ele;
				break;
			case "sID_org3":
				obj.sID_org3 = ele;
				break;
			case "sID_org4":
				obj.sID_org4 = ele;
				break;
			case "sID_org5":
				obj.sID_org5 = ele;
				break;
			case "sID_org6":
				obj.sID_org6 = ele;
				break;
			case "sIDr_org1":
				obj.sIDr_org1 = ele;
				break;
			case "sIDr_org2":
				obj.sIDr_org2 = ele;
				break;
			case "sIDr_org3":
				obj.sIDr_org3 = ele;
				break;
			case "sIDr_org4":
				obj.sIDr_org4 = ele;
				break;
			case "sIDr_org5":
				obj.sIDr_org5 = ele;
				break;
			case "sIDr_org6":
				obj.sIDr_org6 = ele;
				break;
			case "hb1":
				obj.hb1 = ele;
				break;
			case "hb2":
				obj.hb2 = ele;
				break;
			case "hb3":
				obj.hb3 = ele;
				break;
			case "hb4":
				obj.hb4 = ele;
				break;
			case "hb5":
				obj.hb5 = ele;
				break;
			case "hb6":
				obj.hb6 = ele;
				break;
			case "hb7":
				obj.hb7 = ele;
				break;
			case "hb8":
				obj.hb8 = ele;
				break;
			case "hb9":
				obj.hb9 = ele;
				break;
			case "hb10":
				obj.hb10 = ele;
				break;
			case "hbb1":
				obj.hbb1 = ele;
				break;
			case "hbb2":
				obj.hbb2 = ele;
				break;
			case "hbb3":
				obj.hbb3 = ele;
				break;
			case "hbb4":
				obj.hbb4 = ele;
				break;
			case "hbb5":
				obj.hbb5 = ele;
				break;
			case "hbb6":
				obj.hbb6 = ele;
				break;
			case "hbb7":
				obj.hbb7 = ele;
				break;
			case "hbb8":
				obj.hbb8 = ele;
				break;
			case "hbb9":
				obj.hbb9 = ele;
				break;
			case "hbb10":
				obj.hbb10 = ele;
				break;
		}
	}

	public static Element Get_Ircpabe(String index, Ircpabe obj){
		switch (index) {
			case "g1":
				return obj.g1;
			case "g1b":
				return obj.g1b;
			case "g1bb":
				return obj.g1bb;
			case "g2":
				return obj.g2;
			case "g2b":
				return obj.g2b;
			case "e_gg_alpha":
				return obj.e_gg_alpha;
			case "h1":
				return obj.h1;
			case "h2":
				return obj.h2;
			case "h3":
				return obj.h3;
			case "h4":
				return obj.h4;
			case "h5":
				return obj.h5;
			case "h6":
				return obj.h6;
			case "h7":
				return obj.h7;
			case "h8":
				return obj.h8;
			case "h9":
				return obj.h9;
			case "h10":
				return obj.h10;
			case "gsIDs_org1":
				return obj.gsIDs_org1;
			case "gsIDs_org2":
				return obj.gsIDs_org2;
			case "gsIDs_org3":
				return obj.gsIDs_org3;
			case "gsIDs_org4":
				return obj.gsIDs_org4;
			case "gsIDs_org5":
				return obj.gsIDs_org5;
			case "gsIDs_org6":
				return obj.gsIDs_org6;
			case "gbsIDs_org1":
				return obj.gbsIDs_org1;
			case "gbsIDs_org2":
				return obj.gbsIDs_org2;
			case "gbsIDs_org3":
				return obj.gbsIDs_org3;
			case "gbsIDs_org4":
				return obj.gbsIDs_org4;
			case "gbsIDs_org5":
				return obj.gbsIDs_org5;
			case "gbsIDs_org6":
				return obj.gbsIDs_org6;
			case "sID_org1":
				return obj.sID_org1;
			case "sID_org2":
				return obj.sID_org2;
			case "sID_org3":
				return obj.sID_org3;
			case "sID_org4":
				return obj.sID_org4;
			case "sID_org5":
				return obj.sID_org5;
			case "sID_org6":
				return obj.sID_org6;
			case "sIDr_org1":
				return obj.sIDr_org1;
			case "sIDr_org2":
				return obj.sIDr_org2;
			case "sIDr_org3":
				return obj.sIDr_org3;
			case "sIDr_org4":
				return obj.sIDr_org4;
			case "sIDr_org5":
				return obj.sIDr_org5;
			case "sIDr_org6":
				return obj.sIDr_org6;
			case "hb1":
				return obj.hb1;
			case "hb2":
				return obj.hb2;
			case "hb3":
				return obj.hb3;
			case "hb4":
				return obj.hb4;
			case "hb5":
				return obj.hb5;
			case "hb6":
				return obj.hb6;
			case "hb7":
				return obj.hb7;
			case "hb8":
				return obj.hb8;
			case "hb9":
				return obj.hb9;
			case "hb10":
				return obj.hb10;
			case "hbb1":
				return obj.hbb1;
			case "hbb2":
				return obj.hbb2;
			case "hbb3":
				return obj.hbb3;
			case "hbb4":
				return obj.hbb4;
			case "hbb5":
				return obj.hbb5;
			case "hbb6":
				return obj.hbb6;
			case "hbb7":
				return obj.hbb7;
			case "hbb8":
				return obj.hbb8;
			case "hbb9":
				return obj.hbb9;
			case "hbb10":
				return obj.hbb10;
		}
		return null;
	}

	public static byte[] objectToBytes(Element ele){
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;
		byte[] yourBytes = new byte[0];
		try {
			out = new ObjectOutputStream(bos);
			out.writeObject(ele);
			out.flush();
			yourBytes = bos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return yourBytes;
	}
}
