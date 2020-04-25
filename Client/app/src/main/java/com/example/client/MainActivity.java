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

import com.cpabe.abe_lib.bsw.Bswabe;
import com.cpabe.abe_lib.bsw.BswabeMsk;
import com.cpabe.abe_lib.bsw.BswabePrv;
import com.cpabe.abe_lib.bsw.BswabePub;
import com.cpabe.abe_lib.cpabe.*;

public class MainActivity extends Activity {

    TextView textResponse, url, entertex, disp_info, get_priv_key_name;
    EditText editTextAddress, editTextPort;
    Button buttonConnect, buttonClear, enc_button, dec_button;
    EditText welcomeMsg;

    //Encryption Vars
    Cpabe cpabe = new Cpabe();

    static String inputfile;
    static String pubfile;
    static String pubfile2;
    static String mskfile;
    static String mskfile2;
    static String prvfile;
    static String prvfile2;
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
        dec_button = (Button) findViewById(R.id.dec_button);
        entertex = (EditText) findViewById(R.id.entertex);
        get_priv_key_name = (EditText) findViewById(R.id.get_priv_key);

        //for displaying results
        disp_info = (TextView) findViewById(R.id.global_attr);
        disp_info.setText("ta:ta1, ta:ta2, ta:ta3\n"
                + "attr:1, attr:2, attr:3 attr:4, attr:5\n"
                + "attr:6, attr:7, attr:8, attr:9, attr:10");
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
                    textResponse.setText(abe_encrypted());

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
                    boolean flag_dec;
                    flag_dec = abe_decrypt(get_priv_key_name.getText().toString());
                    if(flag_dec){
                        Toast.makeText(MainActivity.this, "Decryption Operates Successfully!", Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("FILE_DECRYPTED/input.txt.new"));
                        //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                    } else {
                        Toast.makeText(MainActivity.this, flag_dec + "Decrypted File does not exist", Toast.LENGTH_LONG).show();
                        textResponse.setText("Wrong Secret Key");
                    }
                } catch (Exception e) {
                    textResponse.setText("There is Exception");
                    e.printStackTrace();
                }
            }
        });
    }

    //ABE encrypt method
    private String abe_encrypted () throws Exception{
        //待加密文件路径
        inputfile = MainActivity.this.getFilesDir() + "/FILE_TO_BE_ENC/input.txt";

        //密钥存储路径
        pubfile   = MainActivity.this.getFilesDir() + "/BSW_ENV/public_keys/ta1.pk";
        pubfile2  = MainActivity.this.getFilesDir() + "/BSW_ENV/public_keys/ta2.pk";
        mskfile   = MainActivity.this.getFilesDir() + "/BSW_ENV/master_keys/ta1.msk";
        mskfile2  = MainActivity.this.getFilesDir() + "/BSW_ENV/master_keys/ta2.msk";

        prvfile   = MainActivity.this.getFilesDir() + "/BSW_ENV/private_keys/ta1.sk";
        prvfile2  = MainActivity.this.getFilesDir() + "/BSW_ENV/private_keys/ta2.sk";

        //加密解密文件存储路径
        encfile =  MainActivity.this.getFilesDir() + "/FILE_ENCRYPTED/input.txt.cpabe";
        decfile = MainActivity.this.getFilesDir() + "/FILE_DECRYPTED/input.txt.new";

        //设置全球公钥属性
        String attribute = "ta:ta1 ta:ta2 ta:ta3 "
                + "attr:1 attr:2 attr:3 attr:4 attr:5 "
                + "attr:6 attr:7 attr:8 attr:9 attr:10";

        //设置私钥属性和加密策略
        String policy = "attr:1 attr:2 attr:3 3of3";
        String policy2 = "attr:1 attr:2 attr:3 ta:ta1 ta:ta2 5of5";

        //生成密钥文件
        cpabe.setup(pubfile, mskfile);
        //cpabe.setup(pubfile2, mskfile2);

        //生成公钥和对应密钥1
        cpabe.keygen(pubfile, prvfile, mskfile, attribute);

        //委派密钥1(添加子集)
        //cpabe.delegate(pubfile, prvfile, "ta:ta1 ta:ta3");

        //生成公钥和对应密钥2
        cpabe.keygen(pubfile, prvfile2, mskfile, attribute);

        //加密
        cpabe.enc(pubfile, policy2, inputfile, encfile);

        return "ABE Encrypt success, encrypted file is stored at \n" + encfile +
                "\n\n The attribute is \n" + attribute +
                "\n\n The policy is \n" + policy +
                "\n\n Three Keys Stored " +
                "\n\n Public_key: \n" + pubfile +
                "\n\n Master key: \n" + mskfile +
                "\n\n Private Key#1 \n" + prvfile;
    }

    //ABE decrypt method
    private boolean abe_decrypt (String priv_key_name) throws Exception{
        pubfile = MainActivity.this.getFilesDir() + "/BSW_ENV/public_keys/ta1.pk";
        prvfile = MainActivity.this.getFilesDir() + "/BSW_ENV/private_keys/" + priv_key_name;

        encfile =  MainActivity.this.getFilesDir() + "/FILE_ENCRYPTED/input.txt.cpabe";
        decfile = MainActivity.this.getFilesDir() + "/FILE_DECRYPTED/input.txt.new";

        //解密
        boolean flag_dec = cpabe.dec(pubfile, prvfile, encfile, decfile);
        if (flag_dec)
            return true;
        return false;
    }

    /*------------------------Utilities------------------------------------*/
    //communication method
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

    //file reader
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

    //file deleter
    private boolean deleteile(String filepath){
        File fileEvents = new File(MainActivity.this.getFilesDir() + "/" + filepath);
        if(fileEvents.delete()){
            return true;
        }
        return false;
    }
}