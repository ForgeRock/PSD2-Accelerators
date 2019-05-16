package com.forgerock.service.accountAndTransaction;

import uk.org.openbanking.datamodel.account.Links;

public class LinksService {
	
	private Links links;
	private static LinksService stdregd = null;

	private LinksService(){
		links = new Links();
    }

	public static LinksService getInstance() {
		if (stdregd == null) {
			stdregd = new LinksService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public Links getDefault(){
		Links links = new Links();
		links.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/account-access-consents/urn-alphabank-intent-88379");

		return links;
	}

}
