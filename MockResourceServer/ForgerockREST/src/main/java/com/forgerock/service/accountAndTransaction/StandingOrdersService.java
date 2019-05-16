package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBExternalStandingOrderStatus1Code;
import uk.org.openbanking.datamodel.account.OBReadStandingOrder4;
import uk.org.openbanking.datamodel.account.OBReadStandingOrder4Data;
import uk.org.openbanking.datamodel.account.OBStandingOrder4;
import uk.org.openbanking.datamodel.payment.OBActiveOrHistoricCurrencyAndAmount;

public class StandingOrdersService {
	
	private static final Logger log = LoggerFactory.getLogger(StandingOrdersService.class);
	
	private OBReadStandingOrder4 response;
	private OBReadStandingOrder4Data data;
	private List<OBStandingOrder4> standingOrderList;
	private static StandingOrdersService stdregd = null;

	private StandingOrdersService() {

		data = new OBReadStandingOrder4Data();
		standingOrderList = getDefaultStandingOrderList();
		data.setStandingOrder(standingOrderList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/standing-orders/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadStandingOrder4();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static StandingOrdersService getInstance() {
		if (stdregd == null) {
			stdregd = new StandingOrdersService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadStandingOrder4 getStandingOrders() {
		data.setStandingOrder(standingOrderList);
		response.setData(data);
		return response;
	}
	
	public OBReadStandingOrder4 getStandingOrdersByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/standing-orders/", accountId);
		List<OBStandingOrder4> newStandingOrderList = new ArrayList<OBStandingOrder4>();
		for (OBStandingOrder4 standingOrder : standingOrderList) {
			if (StringUtils.equals(standingOrder.getAccountId(), accountId)) {
				newStandingOrderList.add(standingOrder);
				break;
			}
		}
		if (newStandingOrderList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Standing-Orders with account id %s not found!", accountId));
		}
		data.setStandingOrder(newStandingOrderList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBStandingOrder4> getDefaultStandingOrderList() {
		
		List<OBStandingOrder4> standingOrderList = new ArrayList<>();
		
		/* First Standing-Order */
		OBStandingOrder4 standingOrder1 = new OBStandingOrder4();
		standingOrder1.setAccountId("22289");
		standingOrder1.setStandingOrderId("Ben3");
		standingOrder1.setFrequency("EvryWorkgDay");
		standingOrder1.setReference("Towbar Club 2 - We Love Towbars");
		standingOrder1.setFirstPaymentDateTime(new DateTime("2017-08-12T00:00:00+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount1 = new OBActiveOrHistoricCurrencyAndAmount();
		amount1.setAmount("0.57");
		amount1.setCurrency("GBP");
		standingOrder1.setFirstPaymentAmount(amount1);
		standingOrder1.setNextPaymentDateTime(new DateTime("2017-08-13T00:00:00+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount2 = new OBActiveOrHistoricCurrencyAndAmount();
		amount2.setAmount("0.56");
		amount2.setCurrency("GBP");
		standingOrder1.setNextPaymentAmount(amount2);
		standingOrder1.setFinalPaymentDateTime(new DateTime("2027-08-12T00:00:00+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount3 = new OBActiveOrHistoricCurrencyAndAmount();
		amount3.setAmount("0.56");
		amount3.setCurrency("GBP");
		standingOrder1.setFinalPaymentAmount(amount3);
		standingOrder1.setStandingOrderStatusCode(OBExternalStandingOrderStatus1Code.ACTIVE);
		
		OBCashAccount3 cashAccount1 = new OBCashAccount3();
		cashAccount1.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount1.setIdentification("80200112345678");
		cashAccount1.setName("Mrs Juniper");
		standingOrder1.setCreditorAccount(cashAccount1);
		standingOrderList.add(standingOrder1);
		
	
		/* Second Standing-Order */
		OBStandingOrder4 standingOrder2 = new OBStandingOrder4();
		standingOrder2.setAccountId("22289");
		standingOrder2.setStandingOrderId("Ben5");
		standingOrder2.setFrequency("WkinMnthDay(2)");
		standingOrder2.setReference("Golf - We Love Golf");
		standingOrder2.setFirstPaymentDateTime(new DateTime("2017-06-12T00:00:00+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount4 = new OBActiveOrHistoricCurrencyAndAmount();
		amount4.setAmount("23.00");
		amount4.setCurrency("GBP");
		standingOrder2.setFirstPaymentAmount(amount4);
		standingOrder2.setNextPaymentDateTime(new DateTime("2017-08-13T00:00:00+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount5 = new OBActiveOrHistoricCurrencyAndAmount();
		amount5.setAmount("23.00");
		amount5.setCurrency("GBP");
		standingOrder2.setNextPaymentAmount(amount5);
		standingOrder2.setFinalPaymentDateTime(new DateTime("2027-08-12T00:00:00+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount6 = new OBActiveOrHistoricCurrencyAndAmount();
		amount6.setAmount("23.00");
		amount6.setCurrency("GBP");
		standingOrder2.setFinalPaymentAmount(amount6);
		standingOrder2.setStandingOrderStatusCode(OBExternalStandingOrderStatus1Code.ACTIVE);
		
		OBCashAccount3 cashAccount2 = new OBCashAccount3();
		cashAccount2.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount2.setIdentification("23605490179017");
		cashAccount2.setName("Mr Tee");
		standingOrder2.setCreditorAccount(cashAccount2);
		standingOrderList.add(standingOrder2);

		return standingOrderList;
	}

}
