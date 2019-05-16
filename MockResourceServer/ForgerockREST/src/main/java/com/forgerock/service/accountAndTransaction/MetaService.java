package com.forgerock.service.accountAndTransaction;

import uk.org.openbanking.datamodel.account.Meta;

public class MetaService {
	
	private Meta meta;
	private static MetaService stdregd = null;

	private MetaService(){
		meta = new Meta();
    }

	public static MetaService getInstance() {
		if (stdregd == null) {
			stdregd = new MetaService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public Meta getDefault(){
		Meta meta = new Meta();
		meta.setTotalPages(1);

		return meta;
	}

}
