/***************************************************************************
 *  Copyright 2019 ForgeRock
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ***************************************************************************/
package com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.consent;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.constants.BerlingGroupConstants.OpenIDM;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.BGAccountsAccessConsentRequest;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.BGAccountsAccessConsentResponse;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.Access;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.Accounts;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.AccountsIDMRequest;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.AllAccounts;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.Balances;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.ClaimsIDMRequest;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.ConsentIDMRequest;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.Transactions;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.account.AccountService;
import com.google.gson.GsonBuilder;

@Service
public class ConsentManagement {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagement.class);

	@Autowired
	ApplicationProperties applicationProperties;
	@Autowired
	AccountService accountService;
	
	public ResponseEntity<String> getOBPaymentConsent(String url, ReqestHeaders idmHeader) {
		log.debug("url: {}", url);
		log.debug("idmHeader: {}", idmHeader);

		HttpHeaders openIdmHeader = new HttpHeaders();
		openIdmHeader.add(OpenIDM.X_OPENIDM_USERNAME, idmHeader.getUsername());
		openIdmHeader.add(OpenIDM.X_OPENIDM_PASSWORD, idmHeader.getPassword());
		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obPaymentConsent = restTemplate.exchange(url, HttpMethod.GET,
				new HttpEntity<Object>(openIdmHeader), String.class);
		log.debug("obPaymentConsent StatusCode : {}", obPaymentConsent.getStatusCode());
		log.debug("obPaymentConsent getBody : {}", obPaymentConsent.getBody());
		return obPaymentConsent;

	}

	public ResponseEntity<String> updateOBPaymentConsent(String url, ReqestHeaders idmHeader, String jsonBody) {
		log.debug("url: {}", url);
		log.debug("idmHeader: {}", idmHeader);
		log.debug("requestConsentToIDM: {}", jsonBody);

		HttpHeaders openIdmHeader = new HttpHeaders();
		openIdmHeader.add(OpenIDM.X_OPENIDM_USERNAME, idmHeader.getUsername());
		openIdmHeader.add(OpenIDM.X_OPENIDM_PASSWORD, idmHeader.getPassword());
		openIdmHeader.add("Content-Type", "application/json");

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obPaymentConsent = restTemplate.exchange(url, HttpMethod.POST,
				new HttpEntity<Object>(jsonBody, openIdmHeader), String.class);
		log.debug("obPaymentConsent StatusCode : {}", obPaymentConsent.getStatusCode());
		log.debug("obPaymentConsent getBody : {}", obPaymentConsent.getBody());
		return obPaymentConsent;

	}

	public String buildPispBody(String sub, String claims, String choosedDebtorAccount) {

		ObjectMapper mapper = new ObjectMapper();
		JsonNode rootNode = mapper.createObjectNode();
		JsonNode consentNode = mapper.createObjectNode();
		ArrayNode arrayNode = mapper.createArrayNode();
		((ObjectNode) consentNode).put("operation", "replace");
		((ObjectNode) consentNode).put("field", "Status");
		((ObjectNode) consentNode).put("value", "AcceptedCustomerProfile");
		arrayNode.add(consentNode);

		JsonNode ibanNode = mapper.createObjectNode();
		if (!StringUtils.isEmpty(choosedDebtorAccount)) {
			((ObjectNode) ibanNode).put("operation", "replace");
			((ObjectNode) ibanNode).put("field", "debtorAccount");
			JsonNode value = mapper.createObjectNode();
			((ObjectNode) value).put("iban", choosedDebtorAccount);
			((ObjectNode) ibanNode).set("value", value);
			arrayNode.add(ibanNode);
		}
		((ObjectNode) rootNode).set("consent", arrayNode);

		JsonNode claimsNode = mapper.createObjectNode();
		((ObjectNode) claimsNode).put("sub", sub);

		JsonNode specificClaimsNode;
		try {
			specificClaimsNode = mapper.readTree(claims);
			((ObjectNode) claimsNode).set("Initiation", specificClaimsNode);
		} catch (IOException e) {
			e.printStackTrace();
		}
		((ObjectNode) rootNode).set("claims", claimsNode);

		return rootNode.toString();
	}

	public String buildAispBody(String sub, List<String> accounts, List<String> balances, List<String> transactions,
			String claims) {

		List<ConsentIDMRequest> consentIDMRequests = new ArrayList<>();
		consentIDMRequests.add(ConsentIDMRequest.builder().operation("replace").field("Status").value("valid").build());
        
		BGAccountsAccessConsentResponse accessConsentResponse = new GsonBuilder().create().fromJson(claims,
                BGAccountsAccessConsentResponse.class);

        
		try {
			
		Access choosedAccess = completeAccessObjectForReplaceInIDM( accounts,  balances,  transactions);
			
			if (choosedAccess != null) {
				
				consentIDMRequests.add(ConsentIDMRequest.builder().operation("replace").field("access")
						.value(choosedAccess).build());
			}
		} catch (Exception e) {
			log.error("{}", e.getMessage());
		}

		List<AccountsIDMRequest> accountsPermmisions = createPermmisonList(accounts, balances, transactions);

		BGAccountsAccessConsentRequest bodyAISPToIDM = null;
		try {
			bodyAISPToIDM = BGAccountsAccessConsentRequest.builder().consent(consentIDMRequests)
					.claims(ClaimsIDMRequest.builder().sub(sub).accounts(accountsPermmisions)
							.combinedServiceIndicator(accessConsentResponse.getCombinedServiceIndicator())
							.frequencyPerDay(accessConsentResponse.getFrequencyPerDay())
							.recurringIndicator(accessConsentResponse.getRecurringIndicator())
							.validUntil(accessConsentResponse.getValidUntil()).build())
					.build();
		} catch (Exception e) {
			log.error("{}", e.getMessage());
		}
		return new GsonBuilder().create().toJson(bodyAISPToIDM).toString();

	}

	private Access completeAccessObjectForReplaceInIDM(List<String> accounts, List<String> balances, List<String> transactions) {
		Access choosedAccess=null;
		
		List<Accounts> accountsAccessList= new ArrayList<>();
		List<Balances> balancesAccessList= new ArrayList<>();
		List<Transactions> transactionsAccessList= new ArrayList<>();
				AllAccounts accountList = accountService.getAllAccounts(
					ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
							.password(applicationProperties.getIdmHeaderPassword()).build());
				 
				if(accountList!=null) {
					accountList.getAccounts().stream().forEach(item->{
						if((accounts!=null&&accounts.contains(item.getResourceId())) 
								|| (accounts!=null&&accounts.contains(item.getIban())) ){
							accountsAccessList.add( Accounts.builder().currency(item.getCurrency()).iban(item.getIban()).build());
						}
						if((balances!=null&&balances.contains(item.getResourceId())) 
								|| (balances!=null&&balances.contains(item.getIban())) ){
							balancesAccessList.add( Balances.builder().currency(item.getCurrency()).iban(item.getIban()).build());
						}
						if((transactions!=null&&transactions.contains(item.getResourceId())) 
								|| (transactions!=null&&transactions.contains(item.getIban())) ){
							transactionsAccessList.add( Transactions.builder().iban(item.getIban()).build());
						}				
					});
					log.debug("size accounts {}, balances {}, tramsactions {} ",accountsAccessList.size(),balancesAccessList.size(),transactionsAccessList.size());
					 choosedAccess=Access.builder().accounts(accountsAccessList).balances(balancesAccessList).transactions(transactionsAccessList).build();
					
				}
		return choosedAccess;
	}

	private List<AccountsIDMRequest> createPermmisonList(List<String> accounts, List<String> balances,
			List<String> transactions) {
		List<AccountsIDMRequest> accountsIDMRequests = new ArrayList<>();

		Set<String> allAccountsId = new HashSet<>();
		if(accounts!=null)allAccountsId.addAll(accounts);
		if(balances!=null)allAccountsId.addAll(balances);
		if(transactions!=null)allAccountsId.addAll(transactions);
		log.debug("allAccountsId: {}", allAccountsId);

		for (String item : allAccountsId) {
			List<String> permmisionList = new ArrayList<>();

			if (accounts!=null&&accounts.contains(item)) {
				permmisionList.add("ReadAccountsDetail");
			}
			if (balances!=null&&balances.contains(item)) {
				permmisionList.add("ReadBalances");
			}
			if (transactions!=null&&transactions.contains(item)) {
				permmisionList.add("ReadTransactions");
			}
			accountsIDMRequests.add(AccountsIDMRequest.builder().accountid(item).permissions(permmisionList).build());

		}

		return accountsIDMRequests;
	}

	public Access getListOfAccountsBalancesTransaction(BGAccountsAccessConsentResponse bgPaymentConsentAISP,
			AllAccounts accountList) {

		List<Accounts> accountsList = new ArrayList<>();
		List<Balances> balancesList = new ArrayList<>();
		List<Transactions> transactionList = new ArrayList<>();

		Map<String, String> listOfIbanResourceID = accountList.getAccounts().stream()
				.collect(Collectors.toMap(Accounts::getIban, Accounts::getResourceId));
		log.debug("listOfIbanResourceID: {}", listOfIbanResourceID);
		try {
			bgPaymentConsentAISP.getAccess().getAccounts().stream().forEach(account -> {
				if (listOfIbanResourceID.containsKey(account.getIban())) {
					accountsList.add(Accounts.builder().resourceId(listOfIbanResourceID.get(account.getIban()))
							.iban(account.getIban()).currency(account.getCurrency()).build());
				}
			});
		} catch (Exception e) {
			log.error("Could not obtain account {}", e.getMessage());
		}
		try {
			bgPaymentConsentAISP.getAccess().getBalances().stream().forEach(balance -> {
				if (listOfIbanResourceID.containsKey(balance.getIban())) {
					balancesList.add(Balances.builder().resourceId(listOfIbanResourceID.get(balance.getIban()))
							.iban(balance.getIban()).currency(balance.getCurrency()).build());
				}
			});
		} catch (Exception e) {
			log.error("Could not obtain balances {}", e.getMessage());
		}
		try {
			bgPaymentConsentAISP.getAccess().getTransactions().stream().forEach(transaction -> {
				if (listOfIbanResourceID.containsKey(transaction.getIban())) {
					transactionList
							.add(Transactions.builder().resourceId(listOfIbanResourceID.get(transaction.getIban()))
									.iban(transaction.getIban()).build());
				}
			});
		} catch (Exception e) {
			log.error("Could not obtain transcation {}", e.getMessage());
		}
		Access resultBGPaymentConsentAISP = Access.builder().accounts(accountsList).balances(balancesList)
				.transactions(transactionList).build();

		return resultBGPaymentConsentAISP;
	}
}
