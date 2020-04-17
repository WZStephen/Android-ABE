package com.vontroy.abe_lib.abe;

/*
 * author: wenzilong,licong
 */

import com.alibaba.fastjson.JSONObject;
import com.vontroy.abe_lib.utils.ISerializable;

import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

public class Ciphertext implements ISerializable {

    private Policy policy;
    private Map<String, Element> components;
    private byte[] load;
    private int[][] matrix;
    private Map<Integer, String> rho;


    public Ciphertext() {
        this.components = new HashMap<String, Element>();
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public void setMatirx(int[][] matrix) {
        this.matrix = matrix;
    }

    public int[][] getMatirx() {
        return matrix;
    }

    public void setRho(Map<Integer, String> rho) {
        this.rho = rho;
    }

    public Map<Integer, String> getRho() {
        return rho;
    }

    public Map<String, Element> getComponents() {
        return components;
    }

    public byte[] getLoad() {
        return load;
    }

    public void setLoad(byte[] load) {
        this.load = load;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("policy:" + policy + "\n");
        sb.append("Components:{\n");
        for (Map.Entry<String, Element> element : getComponents().entrySet()) {
            sb.append(element.getKey() + "--->" + element.getValue() + "\n");
        }
        sb.append("}");
        return sb.toString();
    }

    public String toJSONString() {
        JSONObject obj = new JSONObject();
        obj.put("policy", policy.toString());

//		SerializeUtilBean[] components = new SerializeUtilBean[this.components.size()];
//		int index = 0;
//		for(Map.Entry<String, Element> entry : this.components.entrySet()){
//			components[index] = new SerializeUtilBean(entry.getKey(), entry.getValue().toBytes());
//		}
//		obj.put("components", components);
        for (Map.Entry<String, Element> entry : this.components.entrySet()) {
            obj.put(entry.getKey(), entry.getValue().toBytes());
        }
        obj.put("load", load);

        return obj.toJSONString();
    }
}
