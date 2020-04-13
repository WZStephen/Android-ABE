package com.vontroy.abe_lib.utils;
/*
 * author: licong
 */

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

public class PairingManager {

    private static Logger logger = LoggerFactory.getLogger(PairingManager.class);
    private static final String TYPE_A = "/assets/a.properties";
    //	private static final String TYPE_A = "/src/curves/a.properties";
//	private static final String TYPE_A = "/utils/a.properties"; //for jar
    private static Pairing pairing = null;

    public static void createDefaultPairing() {

//		String url=PairingManager.class.getResource("/").toString();
//		String newUrl = url.substring(6, url.length()-5);
//		newUrl += TYPE_A;
////		System.out.println(newUrl);
//		return PairingFactory.getPairing(new PropertiesParameters().load(newUrl));

        InputStream is = PairingManager.class.getResourceAsStream(TYPE_A);
//		InputStream is = PairingManager.class.getResourceAsStream(TYPE_A);
        pairing = PairingFactory.getPairing(new PropertiesParameters().load(is));
    }

    public static void createPairing(InputStream is) {

        pairing = PairingFactory.getPairing(new PropertiesParameters().load(is));
    }

    public static Pairing getDefaultPairing() {

        if (pairing == null) {
            PairingManager.createDefaultPairing();
            return pairing;
        } else
            return pairing;
    }

}
