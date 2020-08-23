package com.cpabe.abe_lib.bsw;

import java.util.ArrayList;
import java.util.List;

public class Node {
    private List<Node> children;
    private String value;

    public Node(String value) {
        this.children = new ArrayList<>();
        this.value = value;
    }

    public void addChild(Node child){
        children.add(child);
    }

    public String getValue(){
        return value;
    }

    public static List<Node> getChild(Node currentNode){
        List<Node> all_orgs = new ArrayList<>();
        for(int i = 0; i < currentNode.children.size(); i++){
            all_orgs.add(currentNode.children.get(i));
            if(currentNode.children.get(i).children != null){
                all_orgs.add(currentNode.children.get(i).children.get(0));
            }
        }
        return all_orgs;
    }


}
