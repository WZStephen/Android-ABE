package com.vontroy.abe_lib.service;

import com.vontroy.abe_lib.component.PairingCreator;

/**
 * Created by vontroy on 7/15/17.
 */
public class ABEService {
    public ABEService() {
        super();
        PairingCreator.init();
    }

//    public static void main(String[] args) {
//        FileUtils fileUtils = new FileUtils();
//        //初始化KGC
//        KGC kgc = new KGC("center");
//
//        //设置AttributeUniverse
//        String[] attributesSet = {"school:pku", "academy:computer", "籍贯:北京", "age:130"};
//        kgc.setAttributePool(attributesSet);
//
//        // 生成公钥并序列化（执行一次即可）
//        String jsonPK = kgc.initialization();
//
//        // 设置私钥中的属性集合
//        String[] attrStrings = {"school:pku", "academy:computer"};
//
//        //生成私钥并序列化
//        String jsonSK = kgc.genSecretKey(attrStrings);
//
//        String resultStr = "";
//
//        try {
//
//            //————————————————————————————加密部分（运行于客户端）—————————————————————————————————————————
//
//            //设置密文策略
//            String policy = "(school:pku and academy:computer) or (籍贯:北京  and age:130)";
//            //设置明文地址
//            String fileURL = "/home/vontroy/Desktop/abe/a.txt";
//
//            //设置生成密文存放的目录
//            String targetDirURL = "/home/vontroy/Desktop/abe/cipher";
//            //加密文件，得到所在密文地址
//            String ciphertextURL = fileUtils.encFile(fileURL, targetDirURL, policy,
//                    jsonPK, "try it!".getBytes("utf-8"), "jack");
//
//            //————————————————————————————解密部分（运行于客户端）—————————————————————————————————————————
//
//            //执行解密算法,得到明文，返回boolean
//            boolean flag = fileUtils.decFile(ciphertextURL, targetDirURL, jsonSK,
//                    "jerry");
//
//            if (flag)
//                resultStr += "Decryption Operates Successfully!";
//            else
//                resultStr += "Decryption Operates Unsuccessfully!";
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//
//        JSONObject resultJson = new JSONObject();
//        resultJson.put("PK", jsonPK);
//        resultJson.put("SK", jsonSK);
//
//        System.out.println(resultStr);
//    }
}
