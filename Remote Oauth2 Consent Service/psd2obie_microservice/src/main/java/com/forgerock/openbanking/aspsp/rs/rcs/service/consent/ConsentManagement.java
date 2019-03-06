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
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants.OpenIDM;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;

@Service
public class ConsentManagement {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagement.class);

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

	public String buildPispBody(String sub, String claims) {

		ObjectMapper mapper = new ObjectMapper();
		JsonNode rootNode = mapper.createObjectNode();
		JsonNode consentNode = mapper.createObjectNode();
		((ObjectNode) consentNode).put("operation", "replace");
		((ObjectNode) consentNode).put("field", "Status");
		((ObjectNode) consentNode).put("value", "AcceptedCustomerProfile");
		((ObjectNode) rootNode).putArray("consent").add(consentNode);

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

	public String buildAispBody(String sub, String claims, List<String> accounts) {

		ObjectMapper mapper = new ObjectMapper();
		JsonNode rootNode = mapper.createObjectNode();
		JsonNode consentNode = mapper.createObjectNode();
		((ObjectNode) consentNode).put("operation", "replace");
		((ObjectNode) consentNode).put("field", "Status");
		((ObjectNode) consentNode).put("value", "Authorised");
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
}
