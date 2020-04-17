package com.vontroy.abe_lib.component;

import com.vontroy.abe_lib.abe.ABE;
import com.vontroy.abe_lib.abe.Ciphertext;
import com.vontroy.abe_lib.abe.Key;
import com.vontroy.abe_lib.abe.SecretKey;
import com.vontroy.abe_lib.schemes.ZJLW15;
import com.vontroy.abe_lib.utils.Deserialization;
import com.vontroy.abe_lib.utils.SymmetricEncryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Decryptor {
    private String name;
    private ABE scheme;
    private Traceable rScheme;
    private SymmetricEncryption se;
    private Logger logger = LoggerFactory.getLogger(Encryptor.class);

    public Decryptor(String name) {
        this.name = name;
        this.scheme = new ZJLW15();
        this.rScheme = new ZJLW15();
        this.se = new SymmetricEncryption();
    }

    public String getDecryptorName() {
        return this.name;
    }


    /**
     * @return plaintext in form of byte[] , otherwise (failure) return null;
     **/
    public byte[] decrypt(String objCiphertext, String objSecretKey) throws Exception {

        return this.basedecrption(objCiphertext, objSecretKey);
    }

    public boolean Judge(String objSecretKey, String objPK, String ID) {

        return this.baseJudge(objSecretKey, objPK, ID);
    }

    private byte[] basedecrption(String objCiphertext, String objSecretKey) throws Exception {

        if (objCiphertext == null) {
            logger.error("Require Ciphertext!");
        } else if (objSecretKey == null) {
            logger.error("Require SecretKey!");
        }

        byte[] decryptedBytes = null;
        SecretKey sk = Deserialization.toSecretKey(objSecretKey);
        Ciphertext ct = Deserialization.toCiphertext(objCiphertext);

        byte[] symmetricKey = scheme.decrypt(ct, sk);

        //ABE decrypt unsuccessfully;
        if (symmetricKey == null) {
            return null;
        }

        decryptedBytes = se.decrypt(ct.getLoad(), symmetricKey);
        if (decryptedBytes == null) {
            logger.error("AES cipertext is null!");
            return null;
        }
        return decryptedBytes;
    }

    private boolean baseJudge(String objSecretKey, String objPK, String ID) {

        if (objSecretKey == null) {
            logger.error("Require objSecretKey!");
        } else if (objPK == null) {
            logger.error("Require objPK!");
        } else if (ID == null) {
            logger.error("Require ID!");
        }

        SecretKey secretKey = Deserialization.toSecretKey(objSecretKey);
        Key publicKey = Deserialization.toKey(objPK);
        boolean flag = rScheme.trace(secretKey, publicKey, ID);
        return flag;

    }
}