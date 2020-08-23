package com.cpabe.abe_lib.bsw;

import java.util.ArrayList;

import it.unisa.dia.gas.jpbc.Element;

public class BswabePrv {
		/*
		 * A private key
		 */
		Element d; /* G_2 */
		ArrayList<BswabePrvComp> comps; /* BswabePrvComp */

		Element K0;
		Element Lu;
		Element La;
		ArrayList<Ka> Ka_comps;
		ArrayList<Kastr> Kastr_comps;
		ArrayList<Ku> Ku_comps;
		ArrayList<Kustr> Kustr_comps;
		ArrayList<hxstr> hstr_comps;
		ArrayList<hx> hx_comps;
		ArrayList<ht> ht_comps;
		ArrayList<htstr> htstr_comps;
		ArrayList<hbt> hbt_comps;
		ArrayList<hbtstr> hbtstr_comps;
		Element sID;
		Element gbsID;
		Element gbt;
		String ID;
		String org_id;
		}

class Ka{
	String attr;
	Element ele;
}
class Kastr{
	byte[] attr1;
	byte[] attr2;
	byte[] attr3;
	byte[] attr4;
	byte[] attr5;
	byte[] attr6;
	byte[] attr7;
	byte[] attr8;
	byte[] attr9;
	byte[] attr10;
}
class Ku{
	String attr;
	Element ele;
}
class Kustr{
	byte[] attr1;
	byte[] attr2;
	byte[] attr3;
	byte[] attr4;
	byte[] attr5;
	byte[] attr6;
	byte[] attr7;
	byte[] attr8;
	byte[] attr9;
	byte[] attr10;
}
class hx {
	String attr;
	Element ele;
}
class hxstr{
	byte[] attr1;
	byte[] attr2;
	byte[] attr3;
	byte[] attr4;
	byte[] attr5;
	byte[] attr6;
	byte[] attr7;
	byte[] attr8;
	byte[] attr9;
	byte[] attr10;
}

class ht{
	String attr;
	Element ele;
}
class htstr{
	byte[] attr1;
	byte[] attr2;
	byte[] attr3;
	byte[] attr4;
	byte[] attr5;
	byte[] attr6;
	byte[] attr7;
	byte[] attr8;
	byte[] attr9;
	byte[] attr10;
}
class hbt{
	String attr;
	Element ele;
}
class hbtstr{
	byte[] attr1;
	byte[] attr2;
	byte[] attr3;
	byte[] attr4;
	byte[] attr5;
	byte[] attr6;
	byte[] attr7;
	byte[] attr8;
	byte[] attr9;
	byte[] attr10;
}