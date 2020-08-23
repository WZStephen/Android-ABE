package com.vontroy.abe_lib.algorithm;

import com.vontroy.abe_lib.component.Decryptor;
import com.vontroy.abe_lib.component.Encryptor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.StringTokenizer;

public class ABEFileUtils {

    public String encFile(String fileURL, String targetDirURL, String strPolicy, String objPK, byte[] symmetricKey, String ID) throws Exception {

        //File
        File file = new File(fileURL);
        if (!file.exists()) {
            System.out.println("the input file do not exit!");
            return null;
        }

        //FileName
        String fileName = file.getName();

        //call the encryption algorithm , obtain the cipertext (json)
        Encryptor encryptor = new Encryptor(ID);
        String cipertext = encryptor.encrypt(strPolicy, objPK, file, symmetricKey);
        String fullTargetURL = targetDirURL + "/" + "#$$#" + fileName;
        File filePath = new File(targetDirURL);
        if (!filePath.exists()) {
            filePath.mkdir();
        }

        FileOutputStream outputStream = new FileOutputStream(fullTargetURL);
        outputStream.write(cipertext.getBytes());
        outputStream.close();
        return fullTargetURL;
    }

    public boolean decFile(String cipertextURL, String targetDirURL, String objSecretKey, String ID) throws Exception {

        String targetStr = null;
        //obtain the filename and filetype
        StringTokenizer outerST = new StringTokenizer(cipertextURL, "/");
        while (outerST.hasMoreTokens()) {
            targetStr = outerST.nextToken();
        }

        StringTokenizer innerST = new StringTokenizer(targetStr, "#$$#");
        targetStr = innerST.nextToken();

        //load the ciphertext
        String objCiphertext = this.readFile(cipertextURL);

        //call the decryption algorithm , obtain the plaintext (json)
        Decryptor decryptor = new Decryptor(ID);
        byte[] plaintext = decryptor.decrypt(objCiphertext, objSecretKey);
        if (plaintext == null) {
            return false;
        }

        FileOutputStream outputStream = new FileOutputStream(targetDirURL + "/Dec_" + targetStr);
        outputStream.write(plaintext);
        outputStream.close();
        return true;
    }

    public String readFile(String fileName) {

        File file = new File(fileName);
        BufferedReader reader = null;
        String str = "";
        try {
            reader = new BufferedReader(new FileReader(file));
            String tempString = null;

            // read line by line until null
            while ((tempString = reader.readLine()) != null) {
                str = tempString;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e1) {
                }
            }
        }
        return str;
    }
}
