package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBAccount2;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBExternalAccountSubType1Code;
import uk.org.openbanking.datamodel.account.OBExternalAccountType1Code;
import uk.org.openbanking.datamodel.account.OBReadAccount2;
import uk.org.openbanking.datamodel.account.OBReadAccount2Data;

public class AccountsService {
	
	private static final Logger log = LoggerFactory.getLogger(AccountsService.class);
	
	private OBReadAccount2 response;
	private OBReadAccount2Data data;
	private List<OBAccount2> accountList;
	private static AccountsService stdregd = null;

	private AccountsService() {

		data = new OBReadAccount2Data();
		accountList = getDefaultAccountList();
		data.setAccount(accountList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadAccount2();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static AccountsService getInstance() {
		if (stdregd == null) {
			stdregd = new AccountsService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadAccount2 getAccounts() {
		data.setAccount(accountList);
		response.setData(data);
		return response;
	}
	
	public OBReadAccount2 getAccountsByIds(List<String> accountIds, String accountJwt) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/?accounts=%s", accountJwt);
		List<OBAccount2> newAccountList = new ArrayList<OBAccount2>();
		a:for (OBAccount2 obAccount2 : accountList) {
			for (String accountId : accountIds) {
				if (StringUtils.equals(obAccount2.getAccountId(), accountId)) {
					newAccountList.add(obAccount2);
					continue a;
				}
			}
		}

		data.setAccount(newAccountList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	public OBReadAccount2 getAccountById(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s", accountId);
		List<OBAccount2> newAccountList = new ArrayList<OBAccount2>();
		for (OBAccount2 obAccount2 : accountList) {
			if (StringUtils.equals(obAccount2.getAccountId(), accountId)) {
				newAccountList.add(obAccount2);
				break;
			}
		}
		if (newAccountList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Account with id %s not found!", accountId));
		}
		data.setAccount(newAccountList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBAccount2> getDefaultAccountList() {
		
		List<OBAccount2> accountList = new ArrayList<OBAccount2>();
		List<OBCashAccount3> cashAccountList1 = new ArrayList<OBCashAccount3>();
		List<OBCashAccount3> cashAccountList2 = new ArrayList<OBCashAccount3>();
				
		OBAccount2 account1 = new OBAccount2();
		account1.setAccountId("22289");
		account1.setCurrency("GBP");
		account1.setAccountType(OBExternalAccountType1Code.PERSONAL);
		account1.setAccountSubType(OBExternalAccountSubType1Code.CURRENTACCOUNT);
		account1.setNickname("Bills");
		
		OBCashAccount3 cashAccount1 = new OBCashAccount3();
		cashAccount1.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount1.setIdentification("80200110203345");
		cashAccount1.setName("Mr Kevin");
		cashAccount1.setSecondaryIdentification("00021");
		cashAccountList1.add(cashAccount1);
		account1.setAccount(cashAccountList1);
		accountList.add(account1);
		
		
		OBAccount2 account2 = new OBAccount2();
		account2.setAccountId("31820");
		account2.setCurrency("GBP");
		account2.setAccountType(OBExternalAccountType1Code.PERSONAL);
		account2.setAccountSubType(OBExternalAccountSubType1Code.CURRENTACCOUNT);
		account2.setNickname("Household");
		
		OBCashAccount3 cashAccount2 = new OBCashAccount3();
		cashAccount2.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount2.setIdentification("80200110203348");
		cashAccount2.setName("Mr Kevin");
		cashAccountList2.add(cashAccount2);
		account2.setAccount(cashAccountList2);
		accountList.add(account2);

		return accountList;
	}

}
