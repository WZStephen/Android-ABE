package com.vontroy.abe_lib.utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Mapping {

    private static Pairing pairing = PairingManager.getDefaultPairing();

    public static Element bytesToElement(byte[] targetBytes) {

        Element ele = pairing.getGT().newElementFromHash(targetBytes, 0, targetBytes.length);
        return ele;
    }
}
