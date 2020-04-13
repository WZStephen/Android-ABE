package com.vontroy.abe_lib.component;

import com.vontroy.abe_lib.abe.ABE;
import com.vontroy.abe_lib.abe.Key;
import com.vontroy.abe_lib.schemes.ZJLW15;

public class ParameterCenter {
    private static ABE scheme = new ZJLW15();

    public static String[] getParameter() {

        String[] objKeys = new String[2];
        Key[] keys = scheme.setup();
        objKeys[0] = keys[0].toJSONString();
        objKeys[1] = keys[1].toJSONString();
        return objKeys;
    }
}
