package com.vontroy.abe_lib.component;

import com.vontroy.abe_lib.abe.Key;

public interface Traceable {

    boolean trace(Key secretKey, Key publicKey, String ID);
}
