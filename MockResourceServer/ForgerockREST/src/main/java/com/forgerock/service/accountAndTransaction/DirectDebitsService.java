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
import uk.org.openbanking.datamodel.account.OBBeneficiary2;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBDirectDebit1;
import uk.org.openbanking.datamodel.account.OBExternalDirectDebitStatus1Code;
import uk.org.openbanking.datamodel.account.OBReadBeneficiary2;
import uk.org.openbanking.datamodel.account.OBReadBeneficiary2Data;
import uk.org.openbanking.datamodel.account.OBReadDirectDebit1;
import uk.org.openbanking.datamodel.account.OBReadDirectDebit1Data;
import uk.org.openbanking.datamodel.payment.OBActiveOrHistoricCurrencyAndAmount;

public class DirectDebitsService {
	
	private static final Logger log = LoggerFactory.getLogger(DirectDebitsService.class);
	
	private OBReadDirectDebit1 response;
	private OBReadDirectDebit1Data data;
	private List<OBDirectDebit1> directDebitList;
	private static DirectDebitsService stdregd = null;

	private DirectDebitsService() {

		data = new OBReadDirectDebit1Data();
		directDebitList = getDefaultDirectDebitList();
		data.setDirectDebit(directDebitList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/direct-debits/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadDirectDebit1();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static DirectDebitsService getInstance() {
		if (stdregd == null) {
			stdregd = new DirectDebitsService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadDirectDebit1 getDirectDebits() {
		data.setDirectDebit(directDebitList);
		response.setData(data);
		return response;
	}
	
	public OBReadDirectDebit1 getDirectDebitsByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/direct-debits/", accountId);
		List<OBDirectDebit1> newDirectDebitList = new ArrayList<OBDirectDebit1>();
		for (OBDirectDebit1 directDebit : directDebitList) {
			if (StringUtils.equals(directDebit.getAccountId(), accountId)) {
				newDirectDebitList.add(directDebit);
				break;
			}
		}
		if (newDirectDebitList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Direct-Debit with account id %s not found!", accountId));
		}
		data.setDirectDebit(newDirectDebitList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBDirectDebit1> getDefaultDirectDebitList() {
		
		List<OBDirectDebit1> directDebitList = new ArrayList<>();
		
		/* First Direct-Debit */
		OBDirectDebit1 directDebit1 = new OBDirectDebit1();
		directDebit1.setAccountId("22289");
		directDebit1.setDirectDebitId("DD03");
		directDebit1.setMandateIdentification("Caravanners");
		directDebit1.setDirectDebitStatusCode(OBExternalDirectDebitStatus1Code.ACTIVE);
		directDebit1.setName("Towbar Club 3 - We Love Towbars");
		directDebit1.setPreviousPaymentDateTime(new DateTime("2017-04-05T10:43:07+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount1 = new OBActiveOrHistoricCurrencyAndAmount();
		amount1.setAmount("0.57");
		amount1.setCurrency("GBP");
		directDebit1.setPreviousPaymentAmount(amount1);
		directDebitList.add(directDebit1);
		
		
		/* Second Direct-Debit */
		OBDirectDebit1 directDebit2 = new OBDirectDebit1();
		directDebit2.setAccountId("31820");
		directDebit2.setDirectDebitId("DD77");
		directDebit2.setMandateIdentification("Golfers");
		directDebit2.setDirectDebitStatusCode(OBExternalDirectDebitStatus1Code.ACTIVE);
		directDebit2.setName("Golf Club");
		directDebit2.setPreviousPaymentDateTime(new DateTime("2017-05-06T09:00:00+00:00"));
		
		OBActiveOrHistoricCurrencyAndAmount amount2 = new OBActiveOrHistoricCurrencyAndAmount();
		amount2.setAmount("22.30");
		amount2.setCurrency("GBP");
		directDebit2.setPreviousPaymentAmount(amount2);
		directDebitList.add(directDebit2);

		return directDebitList;
	}

}
