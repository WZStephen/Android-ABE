package com.vontroy.abe_lib.schemes;

import com.vontroy.abe_lib.abe.ABE;
import com.vontroy.abe_lib.abe.Attribute;
import com.vontroy.abe_lib.abe.Ciphertext;
import com.vontroy.abe_lib.abe.Key;
import com.vontroy.abe_lib.abe.Policy;
import com.vontroy.abe_lib.abe.SecretKey;
import com.vontroy.abe_lib.component.Traceable;
import com.vontroy.abe_lib.utils.PairingManager;
import com.vontroy.abe_lib.utils.Utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Map.Entry;

//import utils.SymmetricEncryption;

public class ZJLW15 implements ABE, Traceable {

    private Pairing pairing = PairingManager.getDefaultPairing();
    private Logger logger = LoggerFactory.getLogger(ZJLW15.class);


    //		//for testing
//		private Element[] shares; 
    @Override
    public Key[] setup() {

        //Generate master key
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();

        Key masterKey = new Key(Key.Type.MASTER);
        masterKey.getComponents().put("alpha", alpha);
        masterKey.getComponents().put("x", x);
        masterKey.getComponents().put("y", y);

        Element g1 = pairing.getG1().newRandomElement().getImmutable();
        Element g2 = pairing.getG2().newRandomElement().getImmutable();
        Element u = pairing.getG1().newRandomElement().getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element w = pairing.getG1().newRandomElement().getImmutable();
        Element v = pairing.getG1().newRandomElement().getImmutable();
        Element e_gg_alpha = pairing.pairing(g1, g2).powZn(alpha).getImmutable();
        Element X = g2.powZn(x).getImmutable();
        Element Y = g2.powZn(y).getImmutable();

        Key publicKey = new Key(Key.Type.PUBLIC);
        publicKey.getComponents().put("g1", g1);
        publicKey.getComponents().put("g2", g2);
        publicKey.getComponents().put("u", u);
        publicKey.getComponents().put("u", u);
        publicKey.getComponents().put("h", h);
        publicKey.getComponents().put("w", w);
        publicKey.getComponents().put("v", v);
        publicKey.getComponents().put("e_gg_alpha", e_gg_alpha);
        publicKey.getComponents().put("X", X);
        publicKey.getComponents().put("Y", Y);

        //set the key array
        Key[] res = new Key[2];
        res[0] = publicKey;
        res[1] = masterKey;

        //print publickey and masterkey
//			System.out.println(res[0]);
//			System.out.println(res[1]);
        return res;
    }

    @Override
    public SecretKey keygen(Key publicKey, Key masterKey, Attribute[] attributes, String ID) {

        if (publicKey.getType() != Key.Type.PUBLIC) {
            logger.error("require public key!");
        } else if (masterKey.getType() != Key.Type.MASTER) {
            logger.error("require master key!");
        }

        if (attributes == null || attributes.length == 0)
            return null;

        //obtain public parameters
        Element g1, g2, w, h, u, v, X, Y;
        g1 = publicKey.getComponents().get("g1").duplicate().getImmutable();
        g2 = publicKey.getComponents().get("g2").duplicate().getImmutable();
        w = publicKey.getComponents().get("w").duplicate().getImmutable();
        h = publicKey.getComponents().get("h").duplicate().getImmutable();
        u = publicKey.getComponents().get("u").duplicate().getImmutable();
        v = publicKey.getComponents().get("v").duplicate().getImmutable();
        X = publicKey.getComponents().get("X").duplicate().getImmutable();
        Y = publicKey.getComponents().get("Y").duplicate().getImmutable();

        //obtain master key
        Element alpha = masterKey.getComponents().get("alpha").duplicate().getImmutable();
        Element x = masterKey.getComponents().get("x").duplicate().getImmutable();
        Element y = masterKey.getComponents().get("y").duplicate().getImmutable();

        //generate r
        Element r = pairing.getZr().newRandomElement().getImmutable();

        SecretKey sk = new SecretKey();

        //set the attributes associated with secret key
        sk.setAttributes(attributes);

        //Hash ID
        Element id = pairing.getZr().newElementFromBytes(ID.getBytes()).getImmutable();

        // select o , c
        Element o = pairing.getZr().newRandomElement().getImmutable();
        Element c = pairing.getZr().newRandomElement().getImmutable();

        // 1/ (x + ID + yc) =? 0


        //compute K1, L1, L2, L3
        Element K1 = g1.powZn(alpha.div(x.add(id.add(y.mul(c))))).mul(w.powZn(r.mul(o))).getImmutable();
        Element L1 = g2.powZn(r).getImmutable();
        Element L2 = X.powZn(r).getImmutable();
        Element L3 = Y.powZn(r).getImmutable();

        sk.getComponents().put("K1", K1);
        sk.getComponents().put("L1", L1);
        sk.getComponents().put("L2", L2);
        sk.getComponents().put("L3", L3);
        sk.getComponents().put("N1", id);
        sk.getComponents().put("N2", c);
        sk.getComponents().put("N3", o);
        sk.getComponents().put("r", r);


        // init hash function
        MessageDigest sha256_hash = null;

        try {
            sha256_hash = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


        //compute Ktau2 and Ktau3
        for (int i = 0; i < attributes.length; i++) {

            //generate random r tau
            Element rtau = pairing.getZr().newRandomElement().getImmutable();

            //compute Ktau2
            Element Ktau2 = g2.powZn(rtau).getImmutable();

            //hash the attribute to a fixed length.
            sha256_hash.update(attributes[i].toString().getBytes());
            byte[] fixedlengthattr = sha256_hash.digest();

            //otain A tau
            Element Atau = pairing.getZr().newElementFromBytes(fixedlengthattr).getImmutable();

            // compute Ktau3
            Element Ktau3 = (u.powZn(Atau).mul(h)).powZn(rtau).mul(
                    v.powZn(r.mul(x.add(id.add(y.mul(c)))).negate())).getImmutable();
            sk.getComponents().put("K" + attributes[i] + "2", Ktau2);
            sk.getComponents().put("K" + attributes[i] + "3", Ktau3);
        }

        //print secretkey
//			System.out.println(sk);
        return sk;
    }

    @Override
    public Ciphertext encrypt(Key publicKey, Policy policy, byte[] message,
                              byte[] symmetricKey) {

        if (publicKey.getType() != Key.Type.PUBLIC) {
            logger.error("require public key!");
            return null;
        }

        //obtain the public parameters
        Element w = publicKey.getComponents().get("w").duplicate().getImmutable();
        Element v = publicKey.getComponents().get("v").duplicate().getImmutable();
        Element u = publicKey.getComponents().get("u").duplicate().getImmutable();
        Element h = publicKey.getComponents().get("h").duplicate().getImmutable();
        Element g2 = publicKey.getComponents().get("g2").duplicate().getImmutable();
        Element X = publicKey.getComponents().get("X").duplicate().getImmutable();
        Element Y = publicKey.getComponents().get("Y").duplicate().getImmutable();


        Ciphertext ciphertext = new Ciphertext();

        //compute LSSS corresponding to policy
        int[][] matrix = policy.getMatrix();
        Map<Integer, String> rho = policy.getRho();
        if (matrix == null)
            return null;

        //set LSSS
        ciphertext.setMatirx(matrix);
        ciphertext.setRho(rho);

        //generate s
        Element s = pairing.getZr().newRandomElement().getImmutable();
//	        System.out.println("s:"+s.toString());

        // generate vector y.
        Element[] y = new Element[matrix[0].length];
        y[0] = s;
        for (int i = 1; i < y.length; i++) {
            y[i] = pairing.getZr().newRandomElement().getImmutable();
        }

        //compute shares
        Element[] shares = Utils.multiple(matrix, y);
//			System.out.println("shares:");
//			Utils.printArray(shares);

//			//for testing
//			this.shares=shares;

        //set the policy associated with ciphertext
        ciphertext.setPolicy(policy);

        //compute m
        Element m = pairing.getGT().newElementFromHash(symmetricKey, 0, symmetricKey.length);
//			System.out.println("m:" + m);


//		    SymmetricEncryption se = new SymmetricEncryption();
//			//encrypt message
//			try {
//				byte[] messageCihpertext=se.aesEncryptToBytes(message ,m.toBytes());
//				ciphertext.setLoad(messageCihpertext);
//			} catch (Exception e1) {
//				// TODO Auto-generated catch block
//				e1.printStackTrace();
//			}


        //compute C
        Element e_gg_alpha = publicKey.getComponents().get("e_gg_alpha").duplicate();
        Element C = m.mul(e_gg_alpha.powZn(s)).getImmutable();
        ciphertext.getComponents().put("C", C);

        //compute D1, D2, D3
        Element D1 = g2.powZn(s).getImmutable();
        Element D2 = X.powZn(s).getImmutable();
        Element D3 = Y.powZn(s).getImmutable();

        ciphertext.getComponents().put("D1", D1);
        ciphertext.getComponents().put("D2", D2);
        ciphertext.getComponents().put("D3", D3);

        // init hash funcion
        MessageDigest sha256_hash = null;

        try {
            sha256_hash = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        for (int i = 0; i < matrix.length; i++) {

            Element ttau = pairing.getZr().newRandomElement().getImmutable();
            String attr = rho.get(i);

            //hash the attribute to a fixed length.
            sha256_hash.update(attr.getBytes());
            byte[] fixedlengthattr = sha256_hash.digest();

            //compute C_tau_1,C_tau_2
            Element C_tau_1 = w.powZn(shares[i]).mul(v.powZn(ttau)).getImmutable();
            Element C_tau_2 = (u.powZn(pairing.getZr().newElementFromBytes(fixedlengthattr)).mul(h)).powZn(ttau.negate()).getImmutable();
            Element C_tau_3 = g2.powZn(ttau).getImmutable();
            ciphertext.getComponents().put("C" + attr + "1", C_tau_1);
            ciphertext.getComponents().put("C" + attr + "2", C_tau_2);
            ciphertext.getComponents().put("C" + attr + "3", C_tau_3);
        }
//			System.out.println(ciphertext);
        return ciphertext;
    }

    @Override
    public byte[] decrypt(Ciphertext ciphertext, Key secretKey) {

        if (secretKey.getType() != Key.Type.SECRET) {
            logger.error("require secret key!");
        }

        SecretKey sk = (SecretKey) secretKey;

        //obtain the LSSS from ciphertext
        int[][] matrix = ciphertext.getMatirx();
        Map<Integer, String> rho = ciphertext.getRho();


        //get the users' attributes from secretkey
        Attribute[] attributes = sk.getAttributes();

        //attribute matching
        Map<Integer, Integer> setI = Utils.attributesMatching(attributes, rho);

        // compute omega corresponding to set I
        Element[] omega = Utils.computeOmega(matrix, setI);
        if (omega == null) {
            return null;
        }

        //print the recovery value for testing
//			Element[] shares = new Element[setI.size()];
//			Iterator<Integer> keySetIterator = setI.keySet().iterator();
//			for(int i=0;keySetIterator.hasNext();i++){
//			shares[i] = this.shares[keySetIterator.next()];
//				
//			}		
//			System.out.println("innerProduct:" + Utils.innerProduct(shares, omega));

        Attribute[] attrsetI = new Attribute[setI.size()];
        int j = 0;
        for (Entry<Integer, Integer> entry : setI.entrySet()) {

            if (rho.get(entry.getKey()).equals(attributes[entry.getValue()].toString())) {
                attrsetI[j] = attributes[entry.getValue()];
                j++;
            } else logger.error("SetI Error!");
        }

        Element K1 = sk.getComponents().get("K1").duplicate().getImmutable();
        Element N1 = sk.getComponents().get("N1").duplicate().getImmutable();
        Element N2 = sk.getComponents().get("N2").duplicate().getImmutable();

        Element D1 = ciphertext.getComponents().get("D1").duplicate().getImmutable();
        Element D2 = ciphertext.getComponents().get("D2").duplicate().getImmutable();
        Element D3 = ciphertext.getComponents().get("D3").duplicate().getImmutable();


        Element denominator = pairing.pairing(K1, (D1.powZn(N1)).mul(D2.mul(D3.powZn(N2)))).getImmutable();


        Element L1 = sk.getComponents().get("L1").duplicate().getImmutable();
        Element L2 = sk.getComponents().get("L2").duplicate().getImmutable();
        Element L3 = sk.getComponents().get("L3").duplicate().getImmutable();
        Element L = (L1.powZn(N1)).mul(L2.mul(L3.powZn(N2))).getImmutable();
        Element numerator = pairing.getGT().newOneElement().getImmutable();

        for (int i = 0; i < attrsetI.length; i++) {

            Element Ci1 = ciphertext.getComponents().get(
                    "C" + attrsetI[i] + "1").duplicate().getImmutable();

            Element Ci2 = ciphertext.getComponents().get(
                    "C" + attrsetI[i] + "2").duplicate().getImmutable();
            Element Ktau2 = sk.getComponents().get("K" + attrsetI[i] + "2").duplicate().getImmutable();

            Element Ci3 = ciphertext.getComponents().get(
                    "C" + attrsetI[i] + "3").duplicate().getImmutable();
            Element Ktau3 = sk.getComponents().get("K" + attrsetI[i] + "3").duplicate().getImmutable();

            Element t = (pairing.pairing(Ci1, L)
                    .mul(pairing.pairing(Ci2, Ktau2))
                    .mul(pairing.pairing(Ci3, Ktau3))).powZn(omega[i]).getImmutable();

            numerator = numerator.mul(t).getImmutable();

        }

        //obtain C,o
        Element C = ciphertext.getComponents().get("C").duplicate().getImmutable();
        Element o = sk.getComponents().get("N3").duplicate().getImmutable();


        Element res = (C.mul(numerator.powZn(o))).div(denominator).getImmutable();
//	        System.out.println("res:" +res.toString());

//	        byte[] messageCleartext=null;
//	        SymmetricEncryption se =new SymmetricEncryption();
        //decrypt message
//	          try {
//	      			 messageCleartext=se.aesDecryptByBytes(ciphertext.getLoad(), res.toBytes());
//	      		} catch (Exception e1) {
//	      			// TODO Auto-generated catch block
//	      			e1.printStackTrace();
//	      		}
////	        System.out.println("");
//			System.out.println(res);
        return res.toBytes();
    }

    @Override
    public boolean trace(Key secretKey, Key publicKey, String ID) {

        //Hash ID
        Element id = pairing.getZr().newElementFromBytes(ID.getBytes()).getImmutable();


        //obtain pp
        Element w = publicKey.getComponents().get("w").duplicate().getImmutable();
        Element v = publicKey.getComponents().get("v").duplicate().getImmutable();
        Element u = publicKey.getComponents().get("u").duplicate().getImmutable();
        Element h = publicKey.getComponents().get("h").duplicate().getImmutable();
        Element g2 = publicKey.getComponents().get("g2").duplicate().getImmutable();
        Element X = publicKey.getComponents().get("X").duplicate().getImmutable();
        Element Y = publicKey.getComponents().get("Y").duplicate().getImmutable();
        Element e_gg_alpha = publicKey.getComponents().get("e_gg_alpha").duplicate().getImmutable();

        //obtain sk
        Element L1 = secretKey.getComponents().get("L1").duplicate().getImmutable();
        Element L2 = secretKey.getComponents().get("L2").duplicate().getImmutable();
        Element L3 = secretKey.getComponents().get("L3").duplicate().getImmutable();
        Element K1 = secretKey.getComponents().get("K1").duplicate().getImmutable();
        Element N1 = secretKey.getComponents().get("N1").duplicate().getImmutable();
        Element N2 = secretKey.getComponents().get("N2").duplicate().getImmutable();
        Element N3 = secretKey.getComponents().get("N3").duplicate().getImmutable();
        Element r = secretKey.getComponents().get("r").duplicate().getImmutable();

        //obtain one
        Element one = pairing.getGT().newOneElement().getImmutable();


        //compute items for trace
        Element tempOne = pairing.pairing(K1, (g2.powZn(id)).mul(X.mul(Y.powZn(N2)))).getImmutable();

        Element tempTwo = pairing.pairing(w, (L1.powZn(id)).mul(L2.mul(L3.powZn(N2)))).powZn(N3).mul(e_gg_alpha).getImmutable();

//		    Element tempTwo = pairing.pairing(w.powZn(N3.mul(r)), g2.powZn(N1).mul(X.mul(Y.powZn(N2)))).getImmutable();


        if (tempOne.isEqual(tempTwo) && !tempOne.isEqual(one) && !tempTwo.isEqual(one)) {

            return true;
        }

        return false;
    }

    public static void main(String[] args) throws Exception {

        ZJLW15 scheme = new ZJLW15();
        Key[] keys = scheme.setup();


        String ID = "lily";
        Attribute[] attributes = new Attribute[2];
        attributes[0] = new Attribute("school", "pku");
        attributes[1] = new Attribute("academy", "computer");
        Key sk = scheme.keygen(keys[0], keys[1], attributes, "jack");

//			String s = "school:pku and (academy:software or academy:computer)";
        String s = "(school:pku and academy:computer) or (school:mit and academy:software)";
//			String s = "school:pku and academy:computer";
//			String s1 = "(school:pku and academy:software) or (school:mit and academy:computer)";
//			 s1 = "school:mit or academy:software";
        Policy policy = new Policy(s);
        byte[] symmetricKey = "this is the symmetric key bytes".getBytes("utf-8");
        Ciphertext ciphertext = scheme.encrypt(keys[0], policy, "it is a joke".getBytes("utf-8"),
                symmetricKey);

        byte[] messageCleartext = scheme.decrypt(ciphertext, sk);


        if (scheme.trace(sk, keys[0], ID) == true) {

            System.out.println("this is a legal key for user:" + ID);

        } else {

            System.out.println("this is a illegal key for user:" + ID);

        }
//			String strMessageCleartext=new String(messageCleartext,"utf-8");


//			System.out.println(strMessageCleartext);
    }

    public static void printByteArray(byte[] array) {
        for (byte b : array) {
            System.out.print(b + " ");
        }
        System.out.println();
    }
}

