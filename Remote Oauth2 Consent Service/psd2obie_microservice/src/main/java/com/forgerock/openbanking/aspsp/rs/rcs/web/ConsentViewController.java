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
package com.forgerock.openbanking.aspsp.rs.rcs.web;

import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OIDCConstants;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OIDCConstants.OIDCClaim;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants.InternRCS;
import com.forgerock.openbanking.aspsp.rs.rcs.exceptions.OBErrorException;
import com.forgerock.openbanking.aspsp.rs.rcs.model.claims.Claim;
import com.forgerock.openbanking.aspsp.rs.rcs.model.claims.Claims;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.OBPaymentConsentResponse;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.Account;
import com.forgerock.openbanking.aspsp.rs.rcs.service.AMAuthentificationService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.RcsService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.account.AccountService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.consent.ConsentManagement;
import com.forgerock.openbanking.aspsp.rs.rcs.service.jwt.JWTManagementService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.parsing.ParseJWT;
import com.google.gson.GsonBuilder;
import com.nimbusds.jwt.JWTClaimsSet;

import io.swagger.annotations.ApiParam;
import net.minidev.json.JSONObject;

@Controller
public class ConsentViewController {
	private static final Logger log = LoggerFactory.getLogger(ConsentViewController.class);

	@Autowired
	ParseJWT setJwtClaims;
	@Autowired
	RcsService rcsService;
	@Autowired
	JWTManagementService jwtManagementService;
	@Autowired
	ApplicationProperties applicationProperties;
	@Autowired
	ConsentManagement consentManagement;
	@Autowired
	AMAuthentificationService amAuthentificationService;
	@Autowired 
	AccountService accountService;

	@SuppressWarnings("unchecked")
	@GetMapping("/api/rcs/web/consent")
	public String psd2ASPSPConsent(
			@NotNull @ApiParam(value = "Get Scope from AM", required = true) @Valid @RequestParam(value = "consent_request", required = true) String consentRequest,
			@CookieValue(value = "${application.am-cookie-name}", required = false) String ssoToken, Model model) throws Exception {

		log.debug("consent_request: {} ", consentRequest);
		log.debug("@CookieValue  {} ", ssoToken);
		HttpHeaders amHeaderRcsResponse = new HttpHeaders();
		amHeaderRcsResponse.add("Cookie", applicationProperties.getAmCookieName() + "=" + ssoToken);

		try {
			JWTClaimsSet parsedSet = setJwtClaims.parseJWT(consentRequest);

			model.addAttribute("consent_request", consentRequest);
			model.addAttribute("consent_request_field_name", "consent_request");

			final Map<String, String> authInfo = new ObjectMapper().readValue(parsedSet.toString(), Map.class);

			log.debug("authInfo: {} ", authInfo.toString());
			log.debug("scopesList: {} ", authInfo.get("scopes"));
			log.debug("parsedSet.getClaims(): {} ", parsedSet.getClaims().get("scopes"));

			model.addAttribute(InternRCS.CLIENT_NAME, parsedSet.getClaims().get(InternRCS.CLIENT_NAME));
			model.addAttribute(OIDCClaim.STATE, parsedSet.getClaims().get(OIDCClaim.STATE));
			model.addAttribute(InternRCS.USERNAME, parsedSet.getClaims().get(InternRCS.USERNAME));

			final Map<String, String> scopesMap = new ObjectMapper()
					.readValue(parsedSet.getClaims().get("scopes").toString(), Map.class);

			List<String> scopesKey = scopesMap.keySet().stream().collect(Collectors.toList());

			log.debug("scopesKey: {} ", scopesKey);
			model.addAttribute(InternRCS.SCOPES_LIST, scopesKey);

			final Map<String, String> fronClaimsMap = new ObjectMapper().readValue(
					parsedSet.getClaims().get(OpenBankingConstants.IdTokenClaim.CLAIMS).toString(), Map.class);

			List<String> fronClaimsKey = fronClaimsMap.keySet().stream().collect(Collectors.toList());

			Claims claimsMap = Claims.parseClaims(getParsedClaim(parsedSet));
			model.addAttribute(OIDCClaim.CLAIMS, fronClaimsKey);
			log.debug("CONSENT_APPROVAL_REDIRECT_URI: {} ",
					parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));

			String consentID = null;
			try {
				Claim instentId = claimsMap.getUserInfoClaims().get(OpenBankingConstants.IdTokenClaim.INTENT_ID);

				log.debug("claimsMap {} ", claimsMap.toString());
				log.debug("claim.toJson() {} ", instentId.toJson());
				log.debug("claim.getValues() {} ", instentId.getValue().toString());

				consentID = instentId.getValue();
				log.debug("consentID {}", consentID);
				if (!StringUtils.isEmpty(consentID)) {
					List<Account> accountList=accountService.getAllAccounts(ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
										.password(applicationProperties.getIdmHeaderPassword()).build());
					StringBuilder idmURL = new StringBuilder()
							.append(applicationProperties.getIdmGetPaymentIntentConsentUrl()).append(consentID)
							.append("?_prettyPrint=true");

					// ===== PISP =====
					try {
						ResponseEntity<String> obPaymentConsent = consentManagement.getOBPaymentConsent(
								idmURL.toString(),
								ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
										.password(applicationProperties.getIdmHeaderPassword()).build());
						OBPaymentConsentResponse obPaymentConsentPISP = new GsonBuilder().create()
								.fromJson(obPaymentConsent.getBody(), OBPaymentConsentResponse.class);
						if (obPaymentConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
								.value()) {
							model.addAttribute("obPaymentConsentPISP", obPaymentConsentPISP);
							model.addAttribute("flow", OpenBankingConstants.PISP.PISP_FLOW);
							if(accountList!=null) model.addAttribute("accountList", accountList);

							ObjectMapper mapper = new ObjectMapper();
							JsonNode actualObj = mapper.readTree(obPaymentConsent.getBody().toString());
							String initiation = actualObj.get("Data").get("Initiation").toString();
							model.addAttribute("claims", initiation);
						}
					} catch (Exception e) {
						log.error("Could not perform {} ", OpenBankingConstants.PISP.PISP_FLOW, e.getMessage());
						e.printStackTrace();
					}

					idmURL = new StringBuilder().append(applicationProperties.getIdmGetAccountIntentConsentUrl())
							.append(consentID).append("?_prettyPrint=true");

					// ===== AISP =====
					try {
						ResponseEntity<String> obAccountConsent = consentManagement.getOBPaymentConsent(
								idmURL.toString(),
								ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
										.password(applicationProperties.getIdmHeaderPassword()).build());
						log.debug("AISP body: " + obAccountConsent.getBody());
						OBPaymentConsentResponse obPaymentConsentAISP = new GsonBuilder().create()
								.fromJson(obAccountConsent.getBody(), OBPaymentConsentResponse.class);
						if (obAccountConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
								.value()) {
							model.addAttribute("obAccountsAccessConsentAIPS", obPaymentConsentAISP);
							model.addAttribute("flow", OpenBankingConstants.AISP.AISP_FLOW);

							if(accountList!=null)model.addAttribute("accountList", accountList);

							ObjectMapper mapper = new ObjectMapper();
							JsonNode actualObj = mapper.readTree(obAccountConsent.getBody().toString());
							String permissions = actualObj.get("Data").get("Permissions").toString();
							model.addAttribute("claims", permissions);
						}
					} catch (Exception e) {
						log.error("Could not perform {} ", OpenBankingConstants.AISP.AISP_FLOW, e.getMessage());
						e.printStackTrace();
					}

				}
			} catch (Exception e) {
				log.error("Could not obtain {} ", OpenBankingConstants.IdTokenClaim.INTENT_ID, e.getMessage());
			}

		} catch (IOException | ParseException e) {
			log.error("Couldn't serialize response ", e);
		}

		return "consent3.html";
	}

	private JSONObject getParsedClaim(JWTClaimsSet parsedSet)
			throws IOException, JsonParseException, JsonMappingException, ParseException {
		return parsedSet.getJSONObjectClaim(OpenBankingConstants.IdTokenClaim.CLAIMS);
	}

	@PostMapping("/api/rcs/web/consent/sendconsent")
	public String sendConsnet(
			@NotNull @ApiParam(value = "Get Scope from AM", required = true) @Valid @RequestParam(value = "consent_request", required = true) String consentRequestJwt,
			Model model, @RequestParam(value = "scope", required = false) List<String> scopes,
			@RequestParam(value = "account", required = false) List<String> accounts,
			@RequestParam(value = "decision", required = false) String reqestDecision,
			@RequestParam(value = "flow", required = false) String reqestFlow,
			@RequestParam(value = "claims", required = false) String claims,
			@CookieValue(value = "${application.am-cookie-name}", required = false) String ssoToken) {
		try {
			log.debug("@CookieValue  {} ", ssoToken);
			log.debug("Consent body {} ", consentRequestJwt);
			log.debug("Consents prameter {} ", scopes);
			log.debug("Consents accounts {} ", accounts);
			log.debug("ReqestFlow {} ", reqestFlow);
			log.debug("claims {} ", claims);
			JWTClaimsSet parsedSet = setJwtClaims.parseJWT(consentRequestJwt);

			log.debug("Properties amJwkUrl {} ", applicationProperties.getAmJwkUrl());

			boolean decision = "allow".equalsIgnoreCase(reqestDecision);

			Claims claimsMap = Claims.parseClaims(getParsedClaim(parsedSet));
			String consentID = null;
			try {
				Claim instentId = claimsMap.getUserInfoClaims().get(OpenBankingConstants.IdTokenClaim.INTENT_ID);

				log.debug("claimsMap {} ", claimsMap.toString());
				log.debug("claim.toJson() {} ", instentId.toJson());
				log.debug("claim.getValues() {} ", instentId.getValue().toString());

				consentID = instentId.getValue();

				if (!StringUtils.isEmpty(consentID)) {
					StringBuilder idmURL = new StringBuilder();
					String idmRequestBody = "";
					String sub = (String) parsedSet.getClaims().get(OIDCConstants.OIDCClaim.USERNAME);
					if (OpenBankingConstants.PISP.PISP_FLOW.equals(reqestFlow)) {
						idmURL = new StringBuilder().append(applicationProperties.getIdmUpdatePaymentConsentUrl())
								.append(consentID).append("?_action=patch");
						idmRequestBody = consentManagement.buildPispBody(sub, claims,accounts,decision);
					} else if (OpenBankingConstants.AISP.AISP_FLOW.equals(reqestFlow)) {
						idmURL = new StringBuilder().append(applicationProperties.getIdmUpdateAccountConsentUrl())
								.append(consentID).append("?_action=patch");
						idmRequestBody = consentManagement.buildAispBody(sub, claims, accounts,decision);
					}

					log.debug("url {}", idmURL);
					try {
						if (!StringUtils.isEmpty(idmURL)) {
							ResponseEntity<String> entity = consentManagement.updateOBPaymentConsent(
									idmURL.toString(),
									ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
											.password(applicationProperties.getIdmHeaderPassword()).build(),
									idmRequestBody,HttpMethod.POST);
						}
					} catch (Exception e) {
						log.error("Error on updateOBPaymentConsent: ", e.getMessage());
						throw new OBErrorException("Unable to updateOBPaymentConsent!");
					}
				}
			} catch (Exception e) {
				log.error("Could not obtain " + OpenBankingConstants.IdTokenClaim.INTENT_ID, e.getMessage());
			}
			

			log.debug("decision {}  ", decision);

			JWTClaimsSet claimsSet= rcsService.generateRCSConsentResponse(applicationProperties,
					applicationProperties, (String) parsedSet.getClaims().get("csrf"), decision, scopes,
					(String) parsedSet.getClaims().get("clientId"), parsedSet);
			String signedJWT =jwtManagementService.senderSignJWT(claimsSet.toJSONObject().toString(), applicationProperties);			
			log.debug("get signedJWT {}", signedJWT);
			
			//String ecriptedJWT = jwtManagementService.senderSignEncryptJWT( applicationProperties, claimsSet.toJSONObject().toString());
			//log.debug("get ecriptedJWT {}", ecriptedJWT);
			log.debug("REDIRECT_URI: {} ",
					parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));
			model.addAttribute("consent_response", signedJWT);
			model.addAttribute("consent_response_field_name", "consent_response");
			model.addAttribute("redirect_uri",StringUtils.replace(parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI), "null://null/openam", applicationProperties.getAmHostUrl()));

			// Return to AM
			HttpHeaders amHeaderRcsResponse = new HttpHeaders();
			amHeaderRcsResponse.add("Content-Type", "application/x-www-form-urlencoded");
			log.debug("amHeaderRcsResponse: {} ", amHeaderRcsResponse.toString());

		} catch (Exception e) {
			log.error("Couldn't serialize response ", e);
		}

		return "redirectConsentResponseToAM.html";
	}

}