package com.forgerock.service.accountAndTransaction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBAddressTypeCode;
import uk.org.openbanking.datamodel.account.OBExternalPartyType1Code;
import uk.org.openbanking.datamodel.account.OBParty1;
import uk.org.openbanking.datamodel.account.OBPostalAddress8;
import uk.org.openbanking.datamodel.account.OBReadParty1;
import uk.org.openbanking.datamodel.account.OBReadParty1Data;

public class PartyService {
	
	private static final Logger log = LoggerFactory.getLogger(PartyService.class);
	
	private OBReadParty1 response;
	private OBReadParty1Data data;
	private OBParty1 party;
	private static PartyService stdregd = null;

	private PartyService() {

		data = new OBReadParty1Data();
		party = getDefaultParty();
		data.setParty(party);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/party/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadParty1();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static PartyService getInstance() {
		if (stdregd == null) {
			stdregd = new PartyService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadParty1 getParty() {
		data.setParty(party);
		response.setData(data);
		return response;
	}
	
	public OBReadParty1 getPartyByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/party/", accountId);
		OBPostalAddress8 address = new OBPostalAddress8();
		address.setAddressType(OBAddressTypeCode.BUSINESS);
		address.setStreetName("Street");
		address.setBuildingNumber("15");
		address.setPostCode("NW1 1AB");
		address.setTownName("London");
		address.setCountry("GB");
		
		OBParty1 newParty = party;
		newParty.addAddressItem(address);

		data.setParty(newParty);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private OBParty1 getDefaultParty() {
		
		OBParty1 party = new OBParty1();
		party.setPartyId("PXSIF023");
		party.setPartyType(OBExternalPartyType1Code.DELEGATE);
		party.setName("Mr D User");
		party.setEmailAddress("d.user@semiotec.co.jp");
	
		return party;
	}

}
