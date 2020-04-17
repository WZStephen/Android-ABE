package com.example.client;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

//vontroy lib
import com.vontroy.abe_lib.algorithm.ABEFileUtils;
import com.vontroy.abe_lib.component.KGC;
import com.vontroy.abe_lib.component.PairingCreator;

//bsw lib
//import com.cpabe.abe_lib_bsw.*;


//Testing


public class Main2Activity extends Activity {
    private TextView textResponse, entertex, disp_info;
    private Button enc_button, dec_button, dec_button2;

    //Encryption Vars
    private String flag_enc = "False";
    private String flag_dec = "False";
    private String flag_dec2 = "False";
    private String ciphertextURL;
    private String targetDirURL;
    private String jsonSK, jsonSK2;
    private ABEFileUtils fileUtils;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);

        //for ABE encrpt message
        entertex = (EditText) findViewById(R.id.entertex_bsw);
        enc_button = (Button) findViewById(R.id.enc_button_bsw);
        dec_button = (Button) findViewById(R.id.dec_button_bsw);
        dec_button2 = (Button) findViewById(R.id.dec_button2_bsw);

        //for displaying results
        disp_info = (TextView) findViewById(R.id.disp_info_bsw); disp_info.setText("(school:pku & academy:computer) || (location:bj  & age:130)");
        textResponse = (TextView) findViewById(R.id.response_bsw);

        //Encrypt button handler
        enc_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                deletefile("FILE_ENCRYPTED/Dec_tmp.txt");

                File file = new File(Main2Activity.this.getFilesDir(), "/FILE_TO_BE_ENC");
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
                        Toast.makeText(Main2Activity.this, flag_dec, Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("FILE_ENCRYPTED/Dec_tmp.txt"));
                        //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                    } else {
                        Toast.makeText(Main2Activity.this, flag_dec + "Wrong Secret Key", Toast.LENGTH_LONG).show();
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
                        Toast.makeText(Main2Activity.this, flag_dec2, Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("FILE_ENCRYPTED/Dec_tmp.txt"));
                        //deletefile("FILE_ENCRYPTED/Dec_tmp.txt");
                    } else {
                        Toast.makeText(Main2Activity.this, flag_dec2 + "Wrong Secret Key", Toast.LENGTH_LONG).show();
                        textResponse.setText("Decrypted File does not exist");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
    //测试，生成公钥


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
            String fileURL = Main2Activity.this.getFilesDir()+"/FILE_TO_BE_ENC/tmp.txt";
            //设置生成密文存放的目录
            targetDirURL = Main2Activity.this.getFilesDir() + "/FILE_ENCRYPTED";
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
        File fileEvents = new File(Main2Activity.this.getFilesDir() + "/" + filepath);
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
        File fileEvents = new File(Main2Activity.this.getFilesDir() + "/" + filepath);
        if(fileEvents.delete()){
            return true;
        }
        return false;
    }

}
