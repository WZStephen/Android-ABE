package com.vontroy.abe_lib.abe;

/*
 * author: wenzilong,licong
 */

import com.alibaba.fastjson.JSONObject;
import com.vontroy.abe_lib.utils.ISerializable;

import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

public class Key implements ISerializable {

    public static enum Type {PUBLIC, MASTER, SECRET}

    protected Type type;
    protected Map<String, Element> components;

    public Key() {
        this.components = new HashMap<String, Element>();
    }

    public Key(Type type) {
        this();
        this.type = type;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public Map<String, Element> getComponents() {
        return components;
    }

    public String toJSONString() {
        JSONObject obj = new JSONObject();
        obj.put("type", type);

//		SerializeUtilBean[] components = new SerializeUtilBean[this.components.size()];
//		int index = 0;
//		for(Map.Entry<String, Element> entry : this.components.entrySet()){
//			components[index] = new SerializeUtilBean(entry.getKey(), entry.getValue().toBytes());
//		}
//		obj.element("components", components);

        for (Map.Entry<String, Element> entry : this.components.entrySet()) {
            obj.put(entry.getKey(), entry.getValue().toBytes());
        }

        return obj.toJSONString();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Type:" + getType() + "\n");
        sb.append("Components:{\n");
        for (Map.Entry<String, Element> element : getComponents().entrySet()) {
            sb.append(element.getKey() + "---> " + element.getValue() + "\n");
        }
        sb.append("}");
        return sb.toString();
    }
}
