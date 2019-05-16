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
import uk.org.openbanking.datamodel.account.OBBankTransactionCodeStructure1;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBCashBalance1;
import uk.org.openbanking.datamodel.account.OBCreditDebitCode;
import uk.org.openbanking.datamodel.account.OBCreditLine1;
import uk.org.openbanking.datamodel.account.OBEntryStatus1Code;
import uk.org.openbanking.datamodel.account.OBExternalAccountSubType1Code;
import uk.org.openbanking.datamodel.account.OBExternalAccountType1Code;
import uk.org.openbanking.datamodel.account.OBExternalLimitType1Code;
import uk.org.openbanking.datamodel.account.OBReadAccount2;
import uk.org.openbanking.datamodel.account.OBReadAccount2Data;
import uk.org.openbanking.datamodel.account.OBReadBalance1;
import uk.org.openbanking.datamodel.account.OBReadBalance1Data;
import uk.org.openbanking.datamodel.account.OBReadTransaction4;
import uk.org.openbanking.datamodel.account.OBReadTransaction4Data;
import uk.org.openbanking.datamodel.account.OBTransaction3ProprietaryBankTransactionCode;
import uk.org.openbanking.datamodel.account.OBTransaction4;
import uk.org.openbanking.datamodel.account.OBTransactionCashBalance;
import uk.org.openbanking.datamodel.payment.OBActiveOrHistoricCurrencyAndAmount;

public class TransactionsService {
	
	private static final Logger log = LoggerFactory.getLogger(TransactionsService.class);
	
	private OBReadTransaction4 response;
	private OBReadTransaction4Data data;
	private List<OBTransaction4> transactionList;
	private static TransactionsService stdregd = null;

	private TransactionsService() {

		data = new OBReadTransaction4Data();
		transactionList = getDefaultTransactionList();
		data.setTransaction(transactionList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/transactions");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		defaultMeta.setFirstAvailableDateTime(new DateTime("2017-05-03T00:00:00+00:00"));
		defaultMeta.setLastAvailableDateTime(new DateTime("2017-12-03T00:00:00+00:00"));
		
		response = new OBReadTransaction4();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static TransactionsService getInstance() {
		if (stdregd == null) {
			stdregd = new TransactionsService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadTransaction4 getTransactions() {
		data.setTransaction(transactionList);
		response.setData(data);
		return response;
	}
	
	public OBReadTransaction4 getTransactionsByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/transactions/", accountId);
		List<OBTransaction4> newTransactionList = new ArrayList<OBTransaction4>();
		for (OBTransaction4 transaction : transactionList) {
			if (StringUtils.equals(transaction.getAccountId(), accountId)) {
				newTransactionList.add(transaction);
				break;
			}
		}
		if (newTransactionList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Transaction with account id %s not found!", accountId));
		}
		data.setTransaction(newTransactionList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBTransaction4> getDefaultTransactionList() {
		
		List<OBTransaction4> transactionList = new ArrayList<>();
		
		/* First transaction */
		OBTransaction4 transaction1 = new OBTransaction4();
		transaction1.setAccountId("22289");
		transaction1.setTransactionId("123");
		transaction1.setTransactionReference("Ref 123");
		
		OBActiveOrHistoricCurrencyAndAmount amount1 = new OBActiveOrHistoricCurrencyAndAmount();
		amount1.setAmount("10.00");
		amount1.setCurrency("GBP");
		transaction1.setAmount(amount1);
		transaction1.setCreditDebitIndicator(OBCreditDebitCode.CREDIT);
		transaction1.setStatus(OBEntryStatus1Code.BOOKED);
		transaction1.setBookingDateTime(new DateTime("2017-04-05T10:45:22+00:00"));//?????????????????? "date"
		transaction1.setValueDateTime(new DateTime("2017-04-05T10:45:22+00:00"));
		transaction1.setTransactionInformation("Cash from Aubrey");
		
		OBBankTransactionCodeStructure1 bankTransactionCode1 = new OBBankTransactionCodeStructure1();
		bankTransactionCode1.setCode("ReceivedCreditTransfer");
		bankTransactionCode1.setSubCode("DomesticCreditTransfer");
		transaction1.setBankTransactionCode(bankTransactionCode1);
		
		OBTransaction3ProprietaryBankTransactionCode proprietaryBTC1 = new OBTransaction3ProprietaryBankTransactionCode();
		proprietaryBTC1.setCode("Transfer");
		proprietaryBTC1.setIssuer("AlphaBank");
		transaction1.setProprietaryBankTransactionCode(proprietaryBTC1);
		
		OBTransactionCashBalance cashBalance1 = new OBTransactionCashBalance();
		OBActiveOrHistoricCurrencyAndAmount cashBalanceAmount1 = new OBActiveOrHistoricCurrencyAndAmount();
		cashBalanceAmount1.setAmount("230.00");
		cashBalanceAmount1.setCurrency("GBP");
		cashBalance1.setAmount(cashBalanceAmount1);
		cashBalance1.setCreditDebitIndicator(OBCreditDebitCode.CREDIT);
		cashBalance1.setType(OBBalanceType1Code.INTERIMBOOKED);
		transaction1.setBalance(cashBalance1);
		transactionList.add(transaction1);
		
		
		/* Second transaction */
		OBTransaction4 transaction2 = new OBTransaction4();
		transaction2.setAccountId("31820");
		transaction2.setTransactionId("567");
		transaction2.setTransactionReference("Ref 124");
		
		OBActiveOrHistoricCurrencyAndAmount amount2 = new OBActiveOrHistoricCurrencyAndAmount();
		amount2.setAmount("100.00");
		amount2.setCurrency("GBP");
		transaction2.setAmount(amount2);
		transaction2.setCreditDebitIndicator(OBCreditDebitCode.DEBIT);
		transaction2.setStatus(OBEntryStatus1Code.BOOKED);
		transaction2.setBookingDateTime(new DateTime("2017-05-02T14:22:09+00:00"));
		transaction2.setValueDateTime(new DateTime("2017-05-02T14:22:09+00:00"));
		transaction2.setTransactionInformation("Paid the gas bill");
		transaction2.setAddressLine("Coventry");
		
		OBBankTransactionCodeStructure1 bankTransactionCode2 = new OBBankTransactionCodeStructure1();
		bankTransactionCode2.setCode("IssuedCreditTransfer");
		bankTransactionCode2.setSubCode("AutomaticTransfer");
		transaction2.setBankTransactionCode(bankTransactionCode2);
		
		OBTransaction3ProprietaryBankTransactionCode proprietaryBTC2 = new OBTransaction3ProprietaryBankTransactionCode();
		proprietaryBTC2.setCode("DirectDebit");
		proprietaryBTC2.setIssuer("AlphaBank");
		transaction2.setProprietaryBankTransactionCode(proprietaryBTC2);
		
		OBTransactionCashBalance cashBalance2 = new OBTransactionCashBalance();
		OBActiveOrHistoricCurrencyAndAmount cashBalanceAmount2 = new OBActiveOrHistoricCurrencyAndAmount();
		cashBalanceAmount2.setAmount("57.36");
		cashBalanceAmount2.setCurrency("GBP");
		cashBalance2.setAmount(cashBalanceAmount2);
		cashBalance2.setCreditDebitIndicator(OBCreditDebitCode.DEBIT);
		cashBalance2.setType(OBBalanceType1Code.INTERIMBOOKED);
		transaction2.setBalance(cashBalance2);
		transactionList.add(transaction2);

		return transactionList;
	}

}
