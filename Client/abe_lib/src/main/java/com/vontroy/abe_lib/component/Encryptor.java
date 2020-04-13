package com.vontroy.abe_lib.component;

import com.vontroy.abe_lib.abe.ABE;
import com.vontroy.abe_lib.abe.Ciphertext;
import com.vontroy.abe_lib.abe.Key;
import com.vontroy.abe_lib.abe.Policy;
import com.vontroy.abe_lib.schemes.ZJLW15;
import com.vontroy.abe_lib.utils.Deserialization;
import com.vontroy.abe_lib.utils.Mapping;
import com.vontroy.abe_lib.utils.SymmetricEncryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class Encryptor {
    private String name;
    private ABE scheme;
    private Logger logger = LoggerFactory.getLogger(Encryptor.class);
    private SymmetricEncryption se;

    public Encryptor(String name) {
        this.name = name;
        this.scheme = new ZJLW15();
        se = new SymmetricEncryption();
    }

    public String getEncryptorName() {
        return this.name;
    }

    public String encrypt(String strPolicy, String objPK, String message, byte[] symmetricKey) throws Exception {

        return this.baseEncrption(strPolicy, objPK, (Object) message, symmetricKey);

    }

    public String encrypt(String strPolicy, String objPK, File file, byte[] symmetricKey) throws Exception {

        return this.baseEncrption(strPolicy, objPK, (Object) file, symmetricKey);
    }

    private String baseEncrption(String strPolicy, String objPK, Object object, byte[] symmetricKey) throws Exception {

        if (strPolicy == null) {
            logger.error("Require policy!");
        } else if (objPK == null) {
            logger.error("Require PK!");
        } else if (object == null) {
            logger.error("Require message or file!");
        } else if (symmetricKey.length == 0 || symmetricKey == null) {
            logger.error("Require illegel symmetricKey");
        }
        byte[] encryptedBytes = null;
        Key pk = Deserialization.toKey(objPK);
        Policy policy = new Policy(strPolicy);
        Ciphertext ct = scheme.encrypt(pk, policy, null, symmetricKey);
        if (object instanceof String) {
            encryptedBytes = se.encrypt(((String) object).getBytes(), Mapping.bytesToElement(symmetricKey).toBytes());
        } else if (object instanceof File) {
            encryptedBytes = se.encrypt((File) object, Mapping.bytesToElement(symmetricKey).toBytes());
        } else {

            logger.error("type error: not String or File!");
        }

        if (encryptedBytes == null) {
            logger.error("AES cipertext is null!");
            return null;
        } else ct.setLoad(encryptedBytes);
        return ct.toJSONString();
    }


    // public static void main(String[] args) {
    //
    // KGC kgc = new KGC("center");
    // Encryptor enc = new Encryptor("jackson");
    // String[] attributesSet ={"school:pku","academy:computer","����:ɽ��"};
    // kgc.setAttributePool(attributesSet);
    // String jsonPK = kgc.initialization();
    // String policy = "school:pku and academy:computer";
    // String CT = enc.encryption(policy, jsonPK, "I am frank", "oh no".getBytes());
//
// 	}
}
