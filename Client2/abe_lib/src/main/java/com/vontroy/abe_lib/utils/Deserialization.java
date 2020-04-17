package com.vontroy.abe_lib.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.vontroy.abe_lib.abe.Attribute;
import com.vontroy.abe_lib.abe.Ciphertext;
import com.vontroy.abe_lib.abe.Key;
import com.vontroy.abe_lib.abe.Policy;
import com.vontroy.abe_lib.abe.SecretKey;

import java.util.Map.Entry;
import java.util.StringTokenizer;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Deserialization {
    private static Pairing pairing = PairingManager.getDefaultPairing();

    // json to key
    public static Key toKey(String strObj) {

        JSONObject ins = JSON.parseObject(strObj, JSONObject.class);
        Key key = new Key();
        Element ele;

        if (ins.get("type").equals("PUBLIC"))
            key.setType(Key.Type.PUBLIC);

        for (Entry<String, Object> entry : ins.entrySet()) {
            String strIndex = entry.getKey();
            byte[] targetBytes = ins.getBytes(strIndex);
            if (!(strIndex.equals("type"))) {
                if (strIndex.equals("g2") || strIndex.equals("X") || strIndex.equals("Y"))
                    ele = pairing.getG2().newElementFromBytes(targetBytes).getImmutable();
                else if (strIndex.equals("e_gg_alpha"))
                    ele = pairing.getGT().newElementFromBytes(targetBytes).getImmutable();
                else
                    ele = pairing.getG1().newElementFromBytes(targetBytes).getImmutable();
                key.getComponents().put(strIndex, ele);
            }
        }

//		 System.out.println("---------------------------");
//		 System.out.println(key.toString());
//		 System.out.println("---------------------------");

        return key;
    }

    // json to msk
    public static Key toMasterkey(String strObj) {

        JSONObject ins = JSON.parseObject(strObj, JSONObject.class);
        Key key = new Key();
        Element ele = null;

        if (ins.get("type").equals("MASTER"))
            key.setType(Key.Type.MASTER);

        for (Entry<String, Object> entry : ins.entrySet()) {
            String strIndex = entry.getKey();
            byte[] targetBytes = ins.getBytes(strIndex);
            if (!(strIndex.equals("type"))) {
                if (strIndex.equals("alpha") || strIndex.equals("x") || strIndex.equals("y"))
                    ele = pairing.getZr().newElementFromBytes(targetBytes).getImmutable();
                key.getComponents().put(strIndex, ele);
            }
        }
        return key;
    }

    // json to ciphertext
    public static Ciphertext toCiphertext(String strObj) {

        JSONObject ins = JSON.parseObject(strObj, JSONObject.class);
        Ciphertext ct = new Ciphertext();
        Element ele;

        for (Entry<String, Object> entry : ins.entrySet()) {

            if (entry.getKey().equals("policy")) {
                Policy policy = new Policy(entry.getValue().toString());
                ct.setPolicy(policy);
                ct.setMatirx(policy.getMatrix());
                ct.setRho(policy.getRho());
            } else if (entry.getKey().equals("load")) {
                ct.setLoad(ins.getBytes(entry.getKey()));
            } else {
                String strIndex = entry.getKey();
                byte[] targetBytes = ins.getBytes(strIndex);
                if (strIndex.equals("C"))
                    ele = pairing.getGT().newElementFromBytes(targetBytes);
                else if (strIndex.startsWith("D") || strIndex.endsWith("3"))
                    ele = pairing.getG2().newElementFromBytes(targetBytes);
                else
                    ele = pairing.getG1().newElementFromBytes(targetBytes);
                ct.getComponents().put(strIndex, ele);
            }
        }
//		System.out.println("---------------------------");
//		System.out.println(ct.toString());
//		System.out.println("---------------------------");
        return ct;
    }

    // json to secretkey
    public static SecretKey toSecretKey(String strObj) {

        JSONObject ins = JSON.parseObject(strObj, JSONObject.class);
        SecretKey secretKey = new SecretKey();
        Element ele;
        if (ins.get("type").equals("SECRET"))
            secretKey.setType(Key.Type.SECRET);

        for (Entry<String, Object> entry : ins.entrySet()) {

            if (!entry.getKey().equals("attrnum") && !entry.getKey().equals("type")) {
                if (entry.getKey().equals("attributes")) {
                    Attribute[] attributes = new Attribute[Integer.valueOf(ins.get("attrnum").toString())];
                    StringTokenizer st = new StringTokenizer(entry.getValue().toString(), "_");
                    int k = 0;
                    while (st.hasMoreTokens()) {
                        String tmpAttr = st.nextToken();
                        StringTokenizer stnext = new StringTokenizer(tmpAttr, ":");
                        String name = stnext.nextToken().trim();
                        String value = stnext.nextToken().trim();
                        attributes[k] = new Attribute(name, value);
                        k++;
                    }
                    secretKey.setAttributes(attributes);
                } else {
                    String strIndex = entry.getKey();
                    byte[] targetBytes = ins.getBytes(strIndex);
                    if (strIndex.startsWith("N"))
                        ele = pairing.getZr().newElementFromBytes(targetBytes);
                    else if (strIndex.equals("K1") || strIndex.endsWith("2") || strIndex.startsWith("L"))
                        ele = pairing.getG2().newElementFromBytes(targetBytes);
                    else
                        ele = pairing.getG1().newElementFromBytes(targetBytes);

                    secretKey.getComponents().put(strIndex, ele);
                }
            }
        }
//		System.out.println("---------------------------");
//		System.out.println(secretKey.toString());
//		System.out.println("---------------------------");
        return secretKey;
    }
}
