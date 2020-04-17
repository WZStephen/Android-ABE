package com.example.client2;

import android.app.Activity;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.vontroy.abe_lib.algorithm.ABEFileUtils;
import com.vontroy.abe_lib.component.KGC;
import com.vontroy.abe_lib.component.PairingCreator;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {

    TextView textResponse, url, entertex,disp_info;
    EditText editTextAddress, editTextPort;
    Button buttonConnect, buttonClear, enc_button, dec_button, dec_button2, go_button;
    EditText welcomeMsg;

    //Encryption Vars
    //String AES = "AES";
    String flag_enc = "False";
    String flag_dec = "False";
    String flag_dec2 = "False";
    String ciphertextURL;
    String targetDirURL;
    String jsonSK, jsonSK2;
    ABEFileUtils fileUtils;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //for sending message
        editTextAddress = (EditText) findViewById(R.id.address);
        editTextPort = (EditText) findViewById(R.id.port);
        buttonConnect = (Button) findViewById(R.id.connect);
        buttonClear = (Button) findViewById(R.id.clear);
        url = (TextView) findViewById(R.id.url);
        welcomeMsg = (EditText)findViewById(R.id.welcomemsg);

        //for ABE encrpt message
        enc_button = (Button) findViewById(R.id.enc_button);
        dec_button = (Button) findViewById(R.id.dec_button);
        dec_button2 = (Button) findViewById(R.id.dec_button2);

        entertex = (EditText) findViewById(R.id.entertex);
        go_button = (Button) findViewById(R.id.go_button);

        //for displaying results
        disp_info = (TextView) findViewById(R.id.disp_info); disp_info.setText("(school:pku & academy:computer) || (location:bj  & age:130)");
        textResponse = (TextView) findViewById(R.id.response);

        //event handler
        buttonConnect.setOnClickListener(buttonConnectOnClickListener);
        buttonClear.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                textResponse.setText("");
            }
        });

        //Encrypt button handler
        enc_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                deletefile("FILE_ENCRYPTED/Dec_tmp.txt");

                File file = new File(MainActivity.this.getFilesDir(), "/FILE_TO_BE_ENC");
                if (!file.exists()) {
                    file.mkdir();
                }
                try {
                    File gpxfile = new File(file, "tmp.txt");
                    FileWriter writer = new FileWriter(gpxfile);
                    writer.append(entertex.getText().toString());
                    writer.flush();
                    writer.close();
                    //Start encrypt text in textfield
                    flag_enc = abe_encrypted();
                    textResponse.setText(flag_enc);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        //Decrypt button handler
        dec_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                try {
                    flag_dec = abe_decrypt(ciphertextURL, targetDirURL, jsonSK, "jerry");
                    if(flag_dec.equals("Decryption Operates Successfully!")){
                        Toast.makeText(MainActivity.this, flag_dec, Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("FILE_ENCRYPTED/Dec_tmp.txt"));
                        //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                    } else {
                        Toast.makeText(MainActivity.this, flag_dec + "Wrong Secret Key", Toast.LENGTH_LONG).show();
                        textResponse.setText("Decrypted File does not exist");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        //Decrypt button handler2
        dec_button2.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                try {
                    flag_dec2 = abe_decrypt(ciphertextURL, targetDirURL, jsonSK2, "jack");
                    if(flag_dec2.equals("Decryption Operates Successfully!")){
                        Toast.makeText(MainActivity.this, flag_dec2, Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("FILE_ENCRYPTED/Dec_tmp.txt"));
                        //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                    } else {
                        Toast.makeText(MainActivity.this, flag_dec2 + "Wrong Secret Key", Toast.LENGTH_LONG).show();
                        textResponse.setText("Decrypted File does not exist");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
//        //start the new activity
//        go_button.setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                startActivity(new Intent(MainActivity.this, Main2Activity.class));
//            }
//        });

    }


    OnClickListener buttonConnectOnClickListener = new OnClickListener() {
        @Override
        public void onClick(View arg0) {
            String tMsg = welcomeMsg.getText().toString();
            if(tMsg.equals("")){
                tMsg = null;
                Toast.makeText(MainActivity.this, "No Welcome Msg sent", Toast.LENGTH_SHORT).show();
            }
            MyClientTask myClientTask = new MyClientTask(editTextAddress
                    .getText().toString(), Integer.parseInt(editTextPort
                    .getText().toString()),
                    tMsg);
            myClientTask.execute();
        }
    };

    //Communication method
    public class MyClientTask extends AsyncTask<Void, Void, Void> {
        String dstAddress;
        int dstPort;
        String response = "";
        String msgToServer;

        MyClientTask(String addr, int port, String msgTo) {
            dstAddress = addr;
            dstPort = port;
            msgToServer = msgTo;
        }
        @Override
        protected Void doInBackground(Void... arg0) {
            Socket socket = null;
            DataOutputStream dataOutputStream = null;
            DataInputStream dataInputStream = null;
            try {
                socket = new Socket(dstAddress, dstPort);
                dataOutputStream = new DataOutputStream(
                        socket.getOutputStream());
                dataInputStream = new DataInputStream(socket.getInputStream());

                if(msgToServer != null){
                    dataOutputStream.writeUTF(msgToServer);
                }

                response = dataInputStream.readUTF();
            } catch (UnknownHostException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                response = "UnknownHostException: " + e.toString();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                response = "IOException: " + e.toString();
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                if (dataOutputStream != null) {
                    try {
                        dataOutputStream.close();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                if (dataInputStream != null) {
                    try {
                        dataInputStream.close();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
            }
            return null;
        }
        @Override
        protected void onPostExecute(Void result) {
            textResponse.setText(response);
            super.onPostExecute(result);
        }
    }

//    //AES encrypt methods
//    private SecretKeySpec generateKey(String password) throws Exception {
//        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
//        byte[] bytes = password.getBytes("UTF-8");
//        digest.update(bytes, 0, bytes.length);
//        byte[] key = digest.digest();
//        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
//        return secretKeySpec;
//    }
//
//    //AES decrypt methods
//    private String decrypt(String outputString, String password) throws Exception{
//        SecretKeySpec key = generateKey(password);
//        Cipher c = Cipher.getInstance(AES);
//        c.init(Cipher.DECRYPT_MODE, key);
//        byte[] decryptValue = Base64.decode(outputString, Base64.DEFAULT);
//        byte[] decValue = c.doFinal(decryptValue);
//        String decryptedValue = new String(decValue);
//        return decryptedValue;
//    }

    //ABE encrypt method
    private String abe_encrypted () throws Exception{
        PairingCreator.init();
        fileUtils = new ABEFileUtils();
        //初始化KGC
        KGC kgc = new KGC("center");
        String[] attributesSet = {"school:pku", "academy:computer", "location:bj", "age:130"};
        // format "name : value"
        kgc.setAttributePool(attributesSet);
        //生成公钥并序序列化
        String jsonPK = kgc.initialization();
        // 设置私钥中的属性集合
        String[] attrStrings = {"school:pku", "academy:computer"};
        String[] attrStrings2 = {"school:pku", "academy:biology"};

        //生成私钥并序列化
        jsonSK = kgc.genSecretKey(attrStrings, "testID");
        jsonSK2 = kgc.genSecretKey(attrStrings2, "testID2");

        try{
            //设置密文策略
            String policy = "(school:pku and academy:computer) or (location:bj  and age:130)";
            //设置明文地址
            String fileURL = MainActivity.this.getFilesDir()+"/FILE_TO_BE_ENC/tmp.txt";
            //设置生成密文存放的目录
            targetDirURL = MainActivity.this.getFilesDir() + "/FILE_ENCRYPTED";
            //加密文件，得到所在密文地址
            ciphertextURL = fileUtils.encFile(fileURL,targetDirURL, policy, jsonPK, "try it!".getBytes("utf-8"), "kelly");

        } catch (Exception e){
            e.printStackTrace();
        }
        return "ABE Encrypt success, encrypted file is stored at \n" + targetDirURL +
                "\n\n The attribute pair is \n(school:pku and academy:computer) or (location:bj  and age:130) " +
                "\n\n Two Secret Keys Stored \n\n Key#1: \n" + jsonSK + "'\n\n Key#2 \n" + jsonSK2;
    }

    //ABE decrypt method
    private String abe_decrypt (String ciphertexturl, String targetdirurl,  String jsonsk, String id) throws Exception{
        String resultStr = "";
        try{
            boolean flag = fileUtils.decFile(ciphertexturl, targetdirurl, jsonsk,id);
            if (flag){
                resultStr += "Decryption Operates Successfully!";
            }else {
                resultStr += "Decryption Operates Unsuccessfully!";
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        return resultStr;
    }

    //File reader
    private String readFile(String filepath) {
        File fileEvents = new File(MainActivity.this.getFilesDir() + "/" + filepath);
        StringBuilder text = new StringBuilder();
        if(fileEvents.exists()) {
            try {
                BufferedReader br = new BufferedReader(new FileReader(fileEvents));
                String line;
                while ((line = br.readLine()) != null) {
                    text.append(line);
                    text.append('\n');
                }
                br.close();
            } catch (IOException e) {
            }
            String result = text.toString();
            return result;
        } else{
            return filepath + " not exist";
        }
    }

    //File deleter
    private boolean deletefile(String filepath){
        File fileEvents = new File(MainActivity.this.getFilesDir() + "/" + filepath);
        if(fileEvents.delete()){
            return true;
        }
        return false;
    }
}
