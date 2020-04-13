package com.vontroy.abe_lib.abe;

/*
 * interface for all ABE instances
 * all concrete scheme must implements this interface.
 * author: wenzilong,licong
 */

public interface ABE {
    /**
     * @return Key array which contains public key and master key
     */
    Key[] setup();

    /**
     * @param publicKey the public key
     * @param masterKey the master key
     * @param attributes the attributes which used to generate secret key
     * @return secret key
     */
    SecretKey keygen(Key publicKey, Key masterKey, Attribute[] attributes, String ID);

    /**
     * @param publicKey the public key
     * @param policy the policy object
     * @param message the plaintext to be encrypted
     * @param symmetricKey the symmetric key which used to encrypt the message
     * @return ciphertext object
     */
    Ciphertext encrypt(Key publicKey, Policy policy, byte[] message, byte[] symmetricKey);

    /**
     * @param ciphertext the ciphertext
     * @param publicKey	the public key
     * @param secretKey the secret key
     * @return if secret key satisfies the policy in ciphertext, then return the decrypted
     * load of the ciphertext, otherwise return null
     */
    byte[] decrypt(Ciphertext ciphertext , Key secretKey);
}
