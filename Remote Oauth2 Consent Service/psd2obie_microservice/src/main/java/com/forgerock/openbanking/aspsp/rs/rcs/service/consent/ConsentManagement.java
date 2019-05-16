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
package com.forgerock.openbanking.aspsp.rs.rcs.service.consent;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants.OpenIDM;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.SessionTokenAfterAuth;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.Account;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.initiation.DebtorAccount;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.initiation.Initiation;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.domestic_payment.PaymentOrderConsentResponsePayload;
import com.forgerock.openbanking.aspsp.rs.rcs.service.account.AccountService;
import com.forgerock.openbanking.aspsp.rs.rcs.web.rest.util.ConversionUtils;
import com.google.gson.GsonBuilder;



@Service
public class ConsentManagement {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagement.class);

	@Autowired 
	AccountService accountService;
    @Autowired
    ApplicationProperties applicationProperties;
    
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

	public ResponseEntity<String> updateOBPaymentConsent(String url, ReqestHeaders idmHeader, String jsonBody, HttpMethod method) {
		log.debug("url: {}", url);
		log.debug("idmHeader: {}", idmHeader);
		log.debug("requestConsentToIDM: {}", jsonBody);

		HttpHeaders openIdmHeader = new HttpHeaders();
		openIdmHeader.add(OpenIDM.X_OPENIDM_USERNAME, idmHeader.getUsername());
		openIdmHeader.add(OpenIDM.X_OPENIDM_PASSWORD, idmHeader.getPassword());
		openIdmHeader.add("Content-Type", "application/json");

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obPaymentConsent = restTemplate.exchange(url, method,
				new HttpEntity<Object>(jsonBody, openIdmHeader), String.class);
		log.debug("obPaymentConsent StatusCode : {}", obPaymentConsent.getStatusCode());
		log.debug("obPaymentConsent getBody : {}", obPaymentConsent.getBody());
		return obPaymentConsent;

	}
	
	public ResponseEntity<String> updateOBPaymentConsentPatch(String url, ReqestHeaders idmHeader, String jsonBody, HttpMethod method) {
		log.debug("url: {}", url);
		log.debug("idmHeader: {}", idmHeader);
		log.debug("requestConsentToIDM: {}", jsonBody);

		HttpHeaders openIdmHeader = new HttpHeaders();
		openIdmHeader.add(OpenIDM.X_OPENIDM_USERNAME, idmHeader.getUsername());
		openIdmHeader.add(OpenIDM.X_OPENIDM_PASSWORD, idmHeader.getPassword());
		openIdmHeader.add("Content-Type", "application/json");
		openIdmHeader.add("X-HTTP-Method-Override", "PATCH");

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obPaymentConsent = restTemplate.exchange(url, method,
				new HttpEntity<Object>(jsonBody, openIdmHeader), String.class);
		log.debug("obPaymentConsent StatusCode : {}", obPaymentConsent.getStatusCode());
		log.debug("obPaymentConsent getBody : {}", obPaymentConsent.getBody());
		return obPaymentConsent;

	}

	public String buildPispBody(String sub, String claims, List<String> accountList, boolean decision) {
		
		
		
		ObjectMapper mapper = new ObjectMapper();
		JsonNode rootNode = mapper.createObjectNode();
		JsonNode consentNode = mapper.createObjectNode();
		ArrayNode arrayNode = mapper.createArrayNode();
		((ObjectNode) consentNode).put("operation", "replace");
		((ObjectNode) consentNode).put("field", "/Data/Status");
		((ObjectNode) consentNode).put("value", decision?applicationProperties.getIdmConsentStatusAuthorised():applicationProperties.getIdmConsentStatusRejected());
		arrayNode.add(consentNode);
		
		DebtorAccount replacedObject = detectChoosedDebtorAccount(accountList,claims);
		
		JsonNode debtorAccountNode = mapper.createObjectNode();
		if (replacedObject!=null) {
			((ObjectNode) debtorAccountNode).put("operation", "add");
			((ObjectNode) debtorAccountNode).put("field", "/Data/DebtorAccount");
			JsonNode value = mapper.createObjectNode();
			((ObjectNode) value).put("Identification", replacedObject.getIdentification());
			((ObjectNode) value).put("Name", replacedObject.getName());
			((ObjectNode) debtorAccountNode).set("value", value);
			arrayNode.add(debtorAccountNode);
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
	
	private DebtorAccount detectChoosedDebtorAccount(List<String> account, String claims) {
		try {
		Initiation obInitiationPISP = new GsonBuilder().create()
				.fromJson(claims, Initiation.class);
		if(obInitiationPISP!=null&&obInitiationPISP.getDebtorAccount()==null) {
			
			List<Account> accountList=accountService.getAllAccounts(ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
					.password(applicationProperties.getIdmHeaderPassword()).build());
			if(account!=null&&account.size()==1&&accountList.size()>0) {
				accountList.stream().forEach(item->{ 
				if(account.get(0).equalsIgnoreCase( item.getAccountId()))
					obInitiationPISP.setDebtorAccount(DebtorAccount.builder().Identification(item.getAccount().size()>0?item.getAccount().get(0).getIdentification():"").Name(item.getAccount().size()>0?item.getAccount().get(0).getName():"").build());
					}
				);
					
			}
			
			DebtorAccount result = obInitiationPISP.getDebtorAccount();
			
			
			log.debug("DebtorAccount Result: {}",result);
			return result;
		} else {
			log.info("DebtorAccount exist, continue flow");
			return null;
		}
		} catch (Exception e) {
			log.error(" Can't parse Initiation object",e.getMessage());
			return null;
		}
		
	}

	public String buildAispBody(String sub, String claims, List<String> accounts, boolean decision) {

		ObjectMapper mapper = new ObjectMapper();
		JsonNode rootNode = mapper.createObjectNode();
		JsonNode consentNode = mapper.createObjectNode();
		((ObjectNode) consentNode).put("operation", "replace");
		((ObjectNode) consentNode).put("field", "/Data/Status");
		((ObjectNode) consentNode).put("value",  decision?applicationProperties.getIdmConsentStatusAuthorised():applicationProperties.getIdmConsentStatusRejected());
		((ObjectNode) rootNode).putArray("consent").add(consentNode);

		JsonNode claimsNode = mapper.createObjectNode();
		((ObjectNode) claimsNode).put("sub", sub);
		JsonNode specificClaimsNode = mapper.createObjectNode();
		try {
			specificClaimsNode = mapper.readTree(claims);
		} catch (IOException e) {
			e.printStackTrace();
		}
		ArrayNode accountsArrayNode = mapper.createArrayNode();
		for (String account : accounts) {
			if (StringUtils.isNotEmpty(account)) {
				JsonNode accountNode = mapper.createObjectNode();
				((ObjectNode) accountNode).put("accountid", account);
				((ObjectNode) accountNode).set("Permissions", specificClaimsNode);
				accountsArrayNode.add(accountNode);
			}
		}
		((ObjectNode) claimsNode).set("accounts", accountsArrayNode);
		((ObjectNode) rootNode).set("claims", claimsNode);
		return rootNode.toString();
	}
	public String buildAispAutoAcceptBody() throws ParseException, IOException {

		ObjectMapper mapper = new ObjectMapper();
		JsonNode rootNode = mapper.createObjectNode();
		JsonNode consentNode = mapper.createObjectNode();
		((ObjectNode) consentNode).put("operation", "replace");
		((ObjectNode) consentNode).put("field", "/Data/StatusUpdateDateTime");
		((ObjectNode) consentNode).put("value", ConversionUtils.setDateFormating(new Date(),OpenBankingConstants.OpenIDM.IDM_DATE_FORMAT) );
		((ObjectNode) rootNode).putArray("consent").add(consentNode);
		rootNode = (JsonNode) new ObjectMapper().readTree(rootNode.findValue("consent").toString());
		
		return rootNode.toString();
	}
	
	private ResponseEntity<String> redirectToAMgeneric(URI url, HttpHeaders header,MultiValueMap paramFormSend) {
		log.debug("url: {}", url);
		log.debug("idmHeader: {}", header);		

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> responseJWTConsent = restTemplate.postForEntity(url, 
				new HttpEntity<MultiValueMap<String, String>>(paramFormSend, header), String.class);
		
		log.debug("RedirecttoAM StatusCode : {}", responseJWTConsent.getStatusCode());
		log.debug("RedirectToAM getBody : {}", responseJWTConsent.getBody());
		return responseJWTConsent;

	}
	public ResponseEntity redirectToAM(String consentResponse,String urlTo, String ssoToken, ApplicationProperties applicationProperties){
		log.debug("applicationProperties.getRscRemoteHostAm(): {}", applicationProperties.getAmHostUrl());
		urlTo=StringUtils.replace(urlTo, "null://null/openam", applicationProperties.getAmHostUrl());  
		
		//Bug in exchange that encode twice
		//urlTo=StringUtils.replace(urlTo,"%20", " ");
		
		try {
			urlTo = java.net.URLDecoder.decode(urlTo, StandardCharsets.UTF_8.name());
			log.debug("urlTo: {}", urlTo);
		} catch (UnsupportedEncodingException e) {
		    // not going to happen - value came from JDK's own StandardCharsets
		}
		
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(urlTo);
		UriComponents uriComponents = builder.build();
		URI uri = uriComponents.encode().toUri();
		
		HttpHeaders openHeader = new HttpHeaders();	
		openHeader.add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		openHeader.setContentType( MediaType.APPLICATION_FORM_URLENCODED);
		openHeader.add("User-Agent","Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0");
		openHeader.add("Accept-Encoding","gzip, deflate");
		openHeader.add("Accept-Charset", "utf-8");		
		openHeader.add("Cookie", applicationProperties.getAmCookieName()+ "=" + getCookieValue(applicationProperties));
		MultiValueMap<String, String> map =
			    new LinkedMultiValueMap<String, String>();
			map.add("consent_response",consentResponse);
		
		return redirectToAMgeneric( uri,openHeader,map);  
	}
	
	private ResponseEntity<String> getAMToken(String url, HttpHeaders header) {
		log.debug("url: {}", url);
		log.debug("idmHeader: {}", header);		

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> responseJWTConsent = restTemplate.exchange(url, HttpMethod.POST,
				new HttpEntity<Object>(header), String.class);
		
		log.debug("getAMToken StatusCode : {}", responseJWTConsent.getStatusCode());
		log.debug("getAMToken getBody : {}", responseJWTConsent.getBody());
		return responseJWTConsent;

	}
	private String getCookieValue( ApplicationProperties applicationProperties) {
		HttpHeaders openHeader = new HttpHeaders();	
		openHeader.add("Accept-API-Version", "resource=2.0, protocol=1.0");
		openHeader.setContentType( MediaType.APPLICATION_JSON);
		openHeader.add("X-OpenAM-Username", applicationProperties.getAmUsername());
		openHeader.add("X-OpenAM-Password", applicationProperties.getAmPassword());
		try {
		ResponseEntity<String> result= getAMToken(applicationProperties.getAmGetCookieToken(),openHeader);
		if (result.getStatusCode()== HttpStatus.OK) {
			SessionTokenAfterAuth sessionTokenAfterAuth  = new GsonBuilder().create()
					.fromJson(result.getBody(), SessionTokenAfterAuth.class);
			log.debug("sessionTokenAfterAuth getTokenId : {}", sessionTokenAfterAuth.getTokenId());
			return	sessionTokenAfterAuth.getTokenId();			
		}
		} catch (Exception e) {
			log.error("Could not obtain sesstionTokenID:", e.getMessage());
			return "";
		}
		return "";		
	}
}
