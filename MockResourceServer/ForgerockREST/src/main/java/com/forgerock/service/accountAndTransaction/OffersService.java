package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBExternalOfferType1Code;
import uk.org.openbanking.datamodel.account.OBOffer1;
import uk.org.openbanking.datamodel.account.OBReadOffer1;
import uk.org.openbanking.datamodel.account.OBReadOffer1Data;
import uk.org.openbanking.datamodel.payment.OBActiveOrHistoricCurrencyAndAmount;

public class OffersService {
	
	private static final Logger log = LoggerFactory.getLogger(OffersService.class);
	
	private OBReadOffer1 response;
	private OBReadOffer1Data data;
	private List<OBOffer1> offerList;
	private static OffersService stdregd = null;

	private OffersService() {

		data = new OBReadOffer1Data();
		offerList = getDefaultOfferList();
		data.setOffer(offerList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/offers/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadOffer1();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static OffersService getInstance() {
		if (stdregd == null) {
			stdregd = new OffersService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadOffer1 getOffers() {
		data.setOffer(offerList);
		response.setData(data);
		return response;
	}
	
	public OBReadOffer1 getOffersByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/offers/", accountId);
		List<OBOffer1> newOfferList = new ArrayList<OBOffer1>();
		for (OBOffer1 offer : offerList) {
			if (StringUtils.equals(offer.getAccountId(), accountId)) {
				newOfferList.add(offer);
				break;
			}
		}
		if (newOfferList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Offers with account id %s not found!", accountId));
		}
		data.setOffer(newOfferList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBOffer1> getDefaultOfferList() {
		
		List<OBOffer1> offerList = new ArrayList<>();
		
		/* First Offer */
		OBOffer1 offer1 = new OBOffer1();
		offer1.setAccountId("22289");
		offer1.setOfferId("Offer1");
		offer1.setOfferType(OBExternalOfferType1Code.LIMITINCREASE);
		offer1.setDescription("Credit limit increase for the account up to £10000.00");
		OBActiveOrHistoricCurrencyAndAmount amount1 = new OBActiveOrHistoricCurrencyAndAmount();
		amount1.setAmount("10000.00");
		amount1.setCurrency("GBP");
		offer1.setAmount(amount1);
		offerList.add(offer1);
		
		
		/* Second Offer */
		OBOffer1 offer2 = new OBOffer1();
		offer2.setAccountId("22289");
		offer2.setOfferId("Offer2");
		offer2.setOfferType(OBExternalOfferType1Code.BALANCETRANSFER);
		offer2.setDescription("Balance transfer offer up to £2000");
		OBActiveOrHistoricCurrencyAndAmount amount2 = new OBActiveOrHistoricCurrencyAndAmount();
		amount2.setAmount("2000.00");
		amount2.setCurrency("GBP");
		offer2.setAmount(amount2);
		offerList.add(offer2);
		
		
		/* Third Offer */
		OBOffer1 offer3 = new OBOffer1();
		offer3.setAccountId("32515");
		offer3.setOfferId("Offer3");
		offer3.setOfferType(OBExternalOfferType1Code.LIMITINCREASE);
		offer3.setDescription("Credit limit increase for the account up to £50000.00");
		OBActiveOrHistoricCurrencyAndAmount amount3 = new OBActiveOrHistoricCurrencyAndAmount();
		amount3.setAmount("50000.00");
		amount3.setCurrency("GBP");
		offer3.setAmount(amount3);
		offerList.add(offer3);

		return offerList;
	}

}
