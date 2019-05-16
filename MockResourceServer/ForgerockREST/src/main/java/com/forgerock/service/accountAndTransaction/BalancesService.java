package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBAccount2;
import uk.org.openbanking.datamodel.account.OBBalanceType1Code;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBCashBalance1;
import uk.org.openbanking.datamodel.account.OBCreditDebitCode;
import uk.org.openbanking.datamodel.account.OBCreditLine1;
import uk.org.openbanking.datamodel.account.OBExternalAccountSubType1Code;
import uk.org.openbanking.datamodel.account.OBExternalAccountType1Code;
import uk.org.openbanking.datamodel.account.OBExternalLimitType1Code;
import uk.org.openbanking.datamodel.account.OBReadAccount2;
import uk.org.openbanking.datamodel.account.OBReadAccount2Data;
import uk.org.openbanking.datamodel.account.OBReadBalance1;
import uk.org.openbanking.datamodel.account.OBReadBalance1Data;
import uk.org.openbanking.datamodel.payment.OBActiveOrHistoricCurrencyAndAmount;

public class BalancesService {
	
	private static final Logger log = LoggerFactory.getLogger(BalancesService.class);
	
	private OBReadBalance1 response;
	private OBReadBalance1Data data;
	private List<OBCashBalance1> balanceList;
	private static BalancesService stdregd = null;

	private BalancesService() {

		data = new OBReadBalance1Data();
		balanceList = getDefaultBalanceList();
		data.setBalance(balanceList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/balances/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadBalance1();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static BalancesService getInstance() {
		if (stdregd == null) {
			stdregd = new BalancesService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadBalance1 getBalances() {
		data.setBalance(balanceList);
		response.setData(data);
		return response;
	}
	
	public OBReadBalance1 getBalanceByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/balances/", accountId);
		List<OBCashBalance1> newBalanceList = new ArrayList<OBCashBalance1>();
		for (OBCashBalance1 cashBalance1 : balanceList) {
			if (StringUtils.equals(cashBalance1.getAccountId(), accountId)) {
				newBalanceList.add(cashBalance1);
				break;
			}
		}
		if (newBalanceList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Balance with account id %s not found!", accountId));
		}
		data.setBalance(newBalanceList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBCashBalance1> getDefaultBalanceList() {
		
		List<OBCashBalance1> balanceList = new ArrayList<>();
		
		/* First cashBalance */
		OBCashBalance1 cashBalance1 = new OBCashBalance1();
		cashBalance1.setAccountId("22289");
		
		OBActiveOrHistoricCurrencyAndAmount amount1 = new OBActiveOrHistoricCurrencyAndAmount();
		amount1.setAmount("1230.00");
		amount1.setCurrency("GBP");
		cashBalance1.setAmount(amount1);
		cashBalance1.setCreditDebitIndicator(OBCreditDebitCode.CREDIT);
		cashBalance1.setType(OBBalanceType1Code.INTERIMAVAILABLE);
		cashBalance1.setDateTime(new DateTime("2017-04-05T10:43:07+00:00"));
		
		OBCreditLine1 creditLine1 = new OBCreditLine1();
		creditLine1.setIncluded(true);
		OBActiveOrHistoricCurrencyAndAmount creditAmount1 = new OBActiveOrHistoricCurrencyAndAmount();
		creditAmount1.setAmount("1000.00");
		creditAmount1.setCurrency("GBP");
		creditLine1.setAmount(creditAmount1);
		creditLine1.setType(OBExternalLimitType1Code.PRE_AGREED);
		List<OBCreditLine1> creditLineList1 = Arrays.asList(creditLine1);
		cashBalance1.setCreditLine(creditLineList1);
		balanceList.add(cashBalance1);
		
		/* Second cashBalance */
		OBCashBalance1 cashBalance2 = new OBCashBalance1();
		cashBalance2.setAccountId("31820");
		
		OBActiveOrHistoricCurrencyAndAmount amount2 = new OBActiveOrHistoricCurrencyAndAmount();
		amount2.setAmount("57.36");
		amount2.setCurrency("GBP");
		cashBalance2.setAmount(amount2);
		cashBalance2.setCreditDebitIndicator(OBCreditDebitCode.DEBIT);
		cashBalance2.setType(OBBalanceType1Code.INTERIMBOOKED);
		cashBalance2.setDateTime(new DateTime("2017-05-02T14:22:09+00:00"));
		balanceList.add(cashBalance2);

		return balanceList;
	}

}
