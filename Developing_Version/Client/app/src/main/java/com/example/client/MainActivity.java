package com.example.client;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//import abe lib
import com.cpabe.abe_lib.bsw.Node;
import com.cpabe.abe_lib.cpabe.*;

public class MainActivity extends Activity {

    DatabaseHandler mDatabaseHelper;

    TextView textResponse, organization_tf, ta_tf, id_tf, entertext_tf, pubKeyName_tf, prvKeyName_tf;
    EditText editTextAddress, editTextPort, url;
    Button buttonConnect, buttonClear, enc_button, dec_button, clear_button, checkif_button;
    EditText welcomeMsg;

    //Encryption vars
    Cpabe cpabe = new Cpabe();

    static String inputfile;
    static String pubfile, pubfile2, pubfile3, pubfile4, pubfile5, pubfile6, pubfile7, pubfile8, pubfile9, pubfile10;
    static String pubfile_ta1, pubfile_ta2, pubfile_ta3;
    static String mskfile, mskfile2, mskfile3, mskfile4, mskfile5, mskfile6, mskfile7, mskfile8, mskfile9, mskfile10;
    static String mskfile_ta1, mskfile_ta2, mskfile_ta3;
    static String prvfile, prvfile_delegate;
    static String prvfile_ta1, prvfile_ta2, prvfile_ta3;
    static String encfile, del_enc_file, decfile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        //for sending message
//        editTextAddress = (EditText) findViewById(R.id.address);
//        editTextPort = (EditText) findViewById(R.id.port);
//        buttonConnect = (Button) findViewById(R.id.connect);
//        buttonClear = (Button) findViewById(R.id.clear);
//        url = (TextView) findViewById(R.id.url);
//        welcomeMsg = (EditText)findViewById(R.id.welcomemsg);

        //for connecting to database
        mDatabaseHelper = new DatabaseHandler(this);
        mDatabaseHelper.dropTable();

        //for ABE encrpt message
        enc_button = (Button) findViewById(R.id.enc_button);
        dec_button = (Button) findViewById(R.id.dec_button);
        checkif_button = (Button) findViewById(R.id.checkinfo_button);
        clear_button = (Button) findViewById(R.id.clear_button);
        organization_tf = (EditText) findViewById(R.id.orgnization_tf);
        ta_tf = (EditText) findViewById(R.id.ta_tf);
        id_tf = (EditText) findViewById(R.id.id_tf);
        entertext_tf = (EditText) findViewById(R.id.entertext_tf);
        pubKeyName_tf = (EditText) findViewById(R.id.pubKeyName_tf);
        prvKeyName_tf = (EditText) findViewById(R.id.prvKeyName_tf);

        //for display system response
        textResponse = (TextView) findViewById(R.id.response);

//        //connect button handler
//        buttonConnect.setOnClickListener(new View.OnClickListener(){
//            @Override
//            public void onClick(View v) {
//                String tMsg = welcomeMsg.getText().toString();
//                if(tMsg.equals("")){
//                    tMsg = null;
//                    Toast.makeText(MainActivity.this, "No Welcome Msg sent", Toast.LENGTH_SHORT).show();
//                }
//                MyClientTask myClientTask = new MyClientTask(editTextAddress
//                        .getText().toString(), Integer.parseInt(editTextPort
//                        .getText().toString()),
//                        tMsg);
//                myClientTask.execute();
//            }
//        });

//        buttonClear.setOnClickListener(new OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                textResponse.setText("");
//            }
//        });


        //encrypt button handler
        enc_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                //get the input from user
                String organization_tf_text = organization_tf.getText().toString();
                String ta_tf_text = ta_tf.getText().toString();
                String id_tf_text = id_tf.getText().toString();
                String entertext_tf_text = entertext_tf.getText().toString();

                //validate input and begin encryption
                if(!organization_tf_text.isEmpty() && !ta_tf_text.isEmpty() &&
                        !id_tf_text.isEmpty() &&  !entertext_tf_text.isEmpty()){
                    //deletefile("file_encrypted/Dec_tmp.txt");
                    File file = new File(MainActivity.this.getFilesDir(), "/");
                    if (!file.exists()) {
                        file.mkdir();
                    }
                    try {
                        //write input to file waiting for encryption
                        File gpxfile = new File(file, "input.txt");
                        FileWriter writer = new FileWriter(gpxfile);
                        writer.append(entertext_tf.getText().toString());
                        writer.flush();
                        writer.close();

                        //start to encrypt
                        String response = abe_encrypt(organization_tf_text, ta_tf_text, id_tf_text);
                        textResponse.setText(response);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    //write the file into database
                    //File test = new File(MainActivity.this. , "/");
                    boolean isInserted = mDatabaseHelper.addData(organization_tf_text, ta_tf_text, id_tf_text, entertext_tf_text);
                    if(isInserted){
                        Toast.makeText(MainActivity.this, "insert success", Toast.LENGTH_LONG).show();
                    } else{
                        Toast.makeText(MainActivity.this, "insert failed", Toast.LENGTH_LONG).show();
                    }
                }
                else{
                    textResponse.setText("Please input required info!");
                    textResponse.setTextColor(Color.RED);
                }
            }
        });

        //decrypt button handler
        dec_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                try {
                    //Starting decryption
                    boolean flag_dec;
                    flag_dec = abe_decrypt(pubKeyName_tf.getText().toString(),
                            prvKeyName_tf.getText().toString());

                    if(flag_dec){
                        Toast.makeText(MainActivity.this, "Decryption Operates Successfully!", Toast.LENGTH_LONG).show();
                        textResponse.setText(readFile("/input.txt.dec"));
                    } else {
                        Toast.makeText(MainActivity.this, flag_dec + "Decrypted File does not exist", Toast.LENGTH_LONG).show();
                        textResponse.setText("Wrong Secret Key");
                    }
                } catch (Exception e) {
                    textResponse.setText(e.toString());
                }
            }
        });

        //check info button to display the store clients
        checkif_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                Intent intent = new Intent(MainActivity.this, ListDataActivity.class);
                startActivity(intent);
            }

        });

        //clear the response text
        clear_button.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                organization_tf.setText("");
                ta_tf.setText("");
                id_tf.setText("");
                entertext_tf.setText("");
                pubKeyName_tf.setText("");
                prvKeyName_tf.setText("");
                textResponse.setText("");
            }
        });
    }

    //ABE encrypt method
    private String abe_encrypt(String organizationName, String TAName, String id) throws Exception{
        //file path to be encrypted
        inputfile = MainActivity.this.getFilesDir() + "/input.txt";

        //keys store path
        String[] parent_paths = new String[]{"/public_keys", "/master_keys", "/private_keys", "/prvfile_delegate"};

        //create parent directory for storing the keys if not exist
        for(int i = 0; i <=2; i++){
            File file = new File(MainActivity.this.getFilesDir() + parent_paths[i]);
            if (!file.exists()) {file.mkdir();}
        }

        //read user inpit to generate keys
        pubfile   = MainActivity.this.getFilesDir() + "/public_keys/" + TAName +".pk";
        mskfile   = MainActivity.this.getFilesDir() + "/master_keys/" + TAName + ".msk";
        prvfile   = MainActivity.this.getFilesDir() + "/private_keys/" + TAName +".sk";
        prvfile_delegate   = MainActivity.this.getFilesDir() + "/private_keys/" + TAName + "_del.sk";

        //pre-defined keys (testing)
        pubfile_ta1 = MainActivity.this.getFilesDir() + "/public_keys/ta1.pk";
        pubfile_ta2 = MainActivity.this.getFilesDir() + "/public_keys/ta2.pk";
        pubfile_ta3 = MainActivity.this.getFilesDir() + "/public_keys/ta3.pk";
        mskfile_ta1 = MainActivity.this.getFilesDir() + "/master_keys/ta1.msk";
        mskfile_ta2 = MainActivity.this.getFilesDir() + "/master_keys/ta2.msk";
        mskfile_ta3 = MainActivity.this.getFilesDir() + "/master_keys/ta3.msk";
        prvfile_ta1 = MainActivity.this.getFilesDir() + "/private_keys/ta1.org.sk";
        prvfile_ta2 = MainActivity.this.getFilesDir() + "/private_keys/ta2.org.sk";
        prvfile_ta3 = MainActivity.this.getFilesDir() + "/private_keys/ta3.org.sk";
        String[] TAs = new String[]{"ta1", "ta2", "ta3"};
        String[] ta_pk_filenames = new String[]{pubfile_ta1, pubfile_ta2, pubfile_ta3};
        String[] ta_msk_filenames = new String[]{mskfile_ta1, mskfile_ta2, mskfile_ta3};
        String[] ta_sk_filenames = new String[]{prvfile_ta1, prvfile_ta2, prvfile_ta3};

        //define encrypted file path
        encfile =  MainActivity.this.getFilesDir() + "/input.txt.enc";
        del_enc_file =  MainActivity.this.getFilesDir() + "/input.txt.del.enc";
        //define decrypted file path
        decfile = MainActivity.this.getFilesDir() + "/input.txt.dec";
        //set global attribute property
        String[] attr_dict = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
        //set delegated attribute property
        //String[] attr_delegate = {"1", "2", "3", "4"};
        //String[] attr_delegate_ko = {"11", "12"};
        //set private key property and encryption policy
        String policy =
                "1 2 2of2 " +
                "2 3 2of2 " +
                "3 4 2of2 " +
                "5 6 2of2 " +
                "1of4";

        //generate key files
        //cpabe.setup(pubfile, mskfile); //keygen via input
//        cpabe.setup(pubfile_ta1, mskfile_ta1); //keygen via pre-defined key paths(testing)
//        cpabe.setup(pubfile_ta2, mskfile_ta2); //keygen via pre-defined key paths(testing)
//        cpabe.setup(pubfile_ta3, mskfile_ta3); //keygen via pre-defined key paths(testing)

        //federated_setup
        Node root = cpabe.treeStruc(); //a root node contains all the child node in the tree
        for(int i = 0; i < TAs.length; i++){
            cpabe.ta_setup_tree(ta_pk_filenames[i], ta_msk_filenames[i], ta_sk_filenames[i], root);
        }
        for(int i = 0; i < TAs.length-1; i++) {
            cpabe.federated_setup1(ta_pk_filenames[i], ta_pk_filenames[i+1], ta_msk_filenames[i+1], root);
        }

        //federated_keygen
        String[] attr_assigned = attr_dict;
        for(int i = 0; i < TAs.length; i++){
            cpabe.org_keygen(attr_assigned, root, ta_msk_filenames[i], ta_pk_filenames[i], ta_sk_filenames[i]);
        }

        for(int i = 1; i <= TAs.length; i++) {
            cpabe.federated_org_keygen("org1", attr_assigned, ta_msk_filenames[i+1], ta_pk_filenames[i],ta_sk_filenames[i],ta_sk_filenames[i+1], "org1");
        }


        //generate public key and corresponding private keys
        //cpabe.keygen(pubfile, prvfile, mskfile, attr_dict);
        cpabe.keygen(pubfile_ta1, prvfile_ta1, mskfile_ta1, attr_dict);
        cpabe.keygen(pubfile_ta2, prvfile_ta2, mskfile_ta2, attr_dict);
        cpabe.keygen(pubfile_ta3, prvfile_ta3, mskfile_ta3, attr_dict);

        //delegate private keys (add subsets)
        //cpabe.delegate(prvfile_delegate, attr_delegate_ok);

        //encryption
        cpabe.enc(pubfile_ta2, policy, inputfile, encfile); //master encryption
        //cpabe.enc(pubfile, policy, inputfile, del_enc_file); //delegate encryption

        return "Success, enc file is stored at \n" + encfile +
                "\n\n attr_dic: \n" + "{\"1\", \"2\", \"3\", \"4\", \"5\", \"6\", \"7\", \"8\", \"9\", \"10\"}" +
                "\n\n policy \n" + policy +
                "\n\n pub_key: \n" + pubfile +
                "\n\n msk_key: \n" + mskfile +
                "\n\n  prv_Key: \n" + prvfile;
    }

    //ABE decrypt method
    private boolean abe_decrypt(String pub_key_name, String prv_key_name) throws Exception{

        //read the path of public and private keys
        pubfile = MainActivity.this.getFilesDir() + "/public_keys/" + pub_key_name;
        prvfile = MainActivity.this.getFilesDir() + "/private_keys/" + prv_key_name;

        //read the path of the encrypted file
        encfile =  MainActivity.this.getFilesDir() + "/input.txt.enc";
        //encfile =  MainActivity.this.getFilesDir() + "/input.txt.del.enc";

        //set the path of decrypted file
        decfile = MainActivity.this.getFilesDir() + "/input.txt.dec";

        //decryption and return a boolean result
        return cpabe.dec(pubfile, prvfile, encfile, decfile);

    }

    /*-------------------------------------------------------------------------Utilities-------------------------------------------------------------------------------------------------------*/
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





