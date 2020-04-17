package com.vontroy.abe_lib.component;

import com.vontroy.abe_lib.utils.PairingManager;

import java.io.InputStream;

public class PairingCreator {

    public static void init() {
        InputStream is = PairingCreator.class.getResourceAsStream("/assets/a.properties");
        PairingManager.createPairing(is);
        ;
    }
}
