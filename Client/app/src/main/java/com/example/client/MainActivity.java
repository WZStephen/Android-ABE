package com.example.client;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

//import abe lib

import com.cpabe.abe_lib.bsw.*;
import com.cpabe.abe_lib.cpabe.*;

public class MainActivity extends Activity {

    TextView textResponse, url, entertex,disp_info;
    EditText editTextAddress, editTextPort;
    Button buttonConnect, buttonClear, enc_button,enc_button2, dec_button, dec_button2, go_button;
    EditText welcomeMsg;

    //Encryption Vars
    String flag_enc = "False";
    String flag_dec = "False";
    String flag_dec2 = "False";

    static String pubfile;
    static String pubfile2;

    static String mskfile;
    static String mskfile2;

    static String prvfile;
    static String prvfile2;

    static String inputfile;
    static String encfile;
    static String decfile;


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
        enc_button2 = (Button) findViewById(R.id.enc_button2);

        dec_button = (Button) findViewById(R.id.dec_button);
        dec_button2 = (Button) findViewById(R.id.dec_button2);

        entertex = (EditText) findViewById(R.id.entertex);
        go_button = (Button) findViewById(R.id.go_button);

        //for displaying results
        disp_info = (TextView) findViewById(R.id.disp_info); disp_info.setText("(school:pku & academy:computer) || (location:bj  & age:130)");
        textResponse = (TextView) findViewById(R.id.response);

        //connect button handler
        buttonConnect.setOnClickListener(new View.OnClickListener(){
             @Override
             public void onClick(View v) {
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
        });

        buttonClear.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                textResponse.setText("");
            }
        });


        //encrypt button handler
        enc_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                File file = new File(MainActivity.this.getFilesDir(), "/FILE_TO_BE_ENC");
                if (!file.exists()) {
                    file.mkdir();
                }
                try {
                    //写入输入值
                    File gpxfile = new File(file, "input.txt");
                    FileWriter writer = new FileWriter(gpxfile);
                    writer.append(entertex.getText().toString());
                    writer.flush();
                    writer.close();
                    //开始进行加密
                    flag_enc = abe_encrypted();
                    textResponse.setText(flag_enc);
                    abe_encrypted2();
                    textResponse.setText("second key generated");

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });


        //decrypt button handler
        dec_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                try {
                    //开始进行解密
                    flag_dec = abe_decrypt();
                    if(flag_dec.equals("Decryption Operates Successfully!")){
                        Toast.makeText(MainActivity.this, flag_dec, Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("FILE_DECRYPTED/input.txt.new"));
                        //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                    } else {
                        Toast.makeText(MainActivity.this, flag_dec + "Wrong Secret Key", Toast.LENGTH_LONG).show();
                        textResponse.setText("Decrypted File does not exist");
                    }
                } catch (Exception e) {
                    textResponse.setText("Wrong Secret Key or Error");
                    e.printStackTrace();
                }
            }
        });

        //decrypt button handler2
        dec_button2.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                try {
                    flag_dec2 = abe_decrypt2();
                    if(flag_dec2.equals("Decryption Operates Successfully!")){
                        Toast.makeText(MainActivity.this, flag_dec2, Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("FILE_DECRYPTED/input.txt.new"));
                        //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                    } else {
                        Toast.makeText(MainActivity.this, flag_dec2 + "Wrong Secret Key", Toast.LENGTH_LONG).show();
                        textResponse.setText("Decrypted File does not exist");
                    }
                } catch (Exception e) {
                    textResponse.setText("Wrong Secret Key or Error");
                    e.printStackTrace();
                }
            }
        });
        //start the new activity
        go_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //startActivity(new Intent(MainActivity.this, Main2Activity.class));
            }
        });

    }

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


    //ABE encrypt method
    private String abe_encrypted () throws Exception{
        //创建两组不同的公钥和密钥
        pubfile = MainActivity.this.getFilesDir() + "/BSW_ENV/public_keys/pub_key";
        mskfile = MainActivity.this.getFilesDir() + "/BSW_ENV/master_keys/master_key";
        prvfile = MainActivity.this.getFilesDir() + "/BSW_ENV/private_key/prv_key";


        //用第一组公钥和密钥进行加密
        inputfile = MainActivity.this.getFilesDir() + "/FILE_TO_BE_ENC/input.txt";
        encfile =  MainActivity.this.getFilesDir() + "/FILE_ENCRYPTED/input.txt.cpabe";
        decfile = MainActivity.this.getFilesDir() + "/FILE_DECRYPTED/input.txt.new";

        //设置总公钥属性
        String student_attr = "objectClass:inetOrgPerson objectClass:organizationalPerson "
                + "sn:student2 cn:student2 uid:student2 userPassword:student2 "
                + "ou:idp o:computer mail:student2@sdu.edu.cn title:student";


        //设置私钥属性和加密策略
        String student_policy = "sn:student2 cn:student2 uid:student2 3of3";

        //初始化
        Cpabe cpabe = new Cpabe();
        cpabe.setup(pubfile, mskfile);

        //生成公钥和对应密钥
        cpabe.keygen(pubfile, prvfile, mskfile, student_attr);

        //加密
        cpabe.enc(pubfile, student_policy, inputfile, encfile);

        return "ABE Encrypt success, encrypted file is stored at \n" + encfile +
                "\n\n The attribute is \n" + student_attr +
                "\n\n The policy is \n" + student_policy +
                "\n\n Three Keys Stored " +
                "\n\n Public_key: \n" + pubfile +
                "\n\n Master key: \n" + mskfile +
                "\n\n Private Key#1 \n" + prvfile;
    }

    private String abe_encrypted2 () throws Exception{
        pubfile2 = MainActivity.this.getFilesDir() + "/BSW_ENV/public_keys/pub_key2";
        mskfile2 = MainActivity.this.getFilesDir() + "/BSW_ENV/master_keys/master_key2";
        prvfile2 = MainActivity.this.getFilesDir() + "/BSW_ENV/private_key2/prv_key";

        //设置私钥属性和加密策略
        String student_attr2 = "asu:student3 uw:student3";
        //初始化
        Cpabe cpabe = new Cpabe();
        cpabe.setup(pubfile2, mskfile2);

        //生成公钥和对应密钥
        cpabe.keygen(pubfile2, prvfile2, mskfile2, student_attr2);
        return "Testing bed";
    }
    //ABE decrypt method
    private String abe_decrypt () throws Exception{
        pubfile = MainActivity.this.getFilesDir() + "/BSW_ENV/public_keys/pub_key";
        prvfile = MainActivity.this.getFilesDir() + "/BSW_ENV/private_key/prv_key";
        //prvfile = MainActivity.this.getFilesDir() + "/BSW_ENV/private_key2/prv_key";
        encfile =  MainActivity.this.getFilesDir() + "/FILE_ENCRYPTED/input.txt.cpabe";
        decfile = MainActivity.this.getFilesDir() + "/FILE_DECRYPTED/input.txt.new";

        //解密
        Cpabe cpabe = new Cpabe();
        boolean flag_dec = cpabe.dec(pubfile, prvfile, encfile, decfile);
        if (flag_dec == true){
            return "Decryption Operates Successfully!";
        }
        return "Decryption Unsuccessful, Wrong secret key";
    }

    //ABE decrypt method
    private String abe_decrypt2 () throws Exception{
        pubfile = MainActivity.this.getFilesDir() + "/BSW_ENV/public_keys/pub_key";
        //prvfile = MainActivity.this.getFilesDir() + "/BSW_ENV/private_key/prv_key";
        prvfile = MainActivity.this.getFilesDir() + "/BSW_ENV/private_key2/prv_key";
        encfile =  MainActivity.this.getFilesDir() + "/FILE_ENCRYPTED/input.txt.cpabe";
        decfile = MainActivity.this.getFilesDir() + "/FILE_DECRYPTED/input.txt.new";

        //解密
        Cpabe cpabe = new Cpabe();
        boolean flag_dec = cpabe.dec(pubfile, prvfile, encfile, decfile);
        if (flag_dec == true){
            return "Decryption Operates Successfully!";
        }
        return "Decryption Unsuccessful, Wrong secret key";
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