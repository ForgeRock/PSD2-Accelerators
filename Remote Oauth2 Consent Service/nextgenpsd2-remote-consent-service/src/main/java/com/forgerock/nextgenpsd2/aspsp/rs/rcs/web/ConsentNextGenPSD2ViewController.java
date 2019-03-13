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
package com.forgerock.nextgenpsd2.aspsp.rs.rcs.web;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
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
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.constants.BerlingGroupConstants;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.constants.OIDCConstants;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.exceptions.OBErrorException;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.claims.Claims;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.BGAccountsAccessConsentResponse;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.BGPaymentConsentResponse;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.Access;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.AllAccounts;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.DebtorAccount;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.payment.PaymentConfirmationResponse;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.payment.PaymentConfirmationResquest;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.AMAuthentificationService;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.RcsService;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.account.AccountService;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.consent.ConsentManagement;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.jwt.JWTManagementService;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.parsing.ParseJWT;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.payment.PaymentService;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.web.utils.ConsentUtils;
import com.google.gson.GsonBuilder;
import com.nimbusds.jwt.JWTClaimsSet;

import io.swagger.annotations.ApiParam;
import net.minidev.json.JSONObject;

@Controller
public class ConsentNextGenPSD2ViewController {
	private static final Logger log = LoggerFactory.getLogger(ConsentNextGenPSD2ViewController.class);

	private final String SCOPES_LIST = "scopeList";

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
	@Autowired
	ConsentUtils consentUtils;
	@Autowired
	PaymentService paymentService;

	@SuppressWarnings("unchecked")
	@GetMapping("/api/rcs/consent")
	public String psd2ASPSPConsent(
			@NotNull @ApiParam(value = "Get Scope from AM", required = true) @Valid @RequestParam(value = "consent_request", required = true) String consentRequest,
			@CookieValue(value = "${application.am-cookie-name}", required = false) String ssoToken, Model model) {

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

			model.addAttribute(OIDCConstants.OIDCClaim.CLIENT_NAME,
					parsedSet.getClaims().get(OIDCConstants.OIDCClaim.CLIENT_NAME));
			model.addAttribute(OIDCConstants.OIDCClaim.STATE, parsedSet.getClaims().get(OIDCConstants.OIDCClaim.STATE));
			model.addAttribute(OIDCConstants.OIDCClaim.USERNAME,
					parsedSet.getClaims().get(OIDCConstants.OIDCClaim.USERNAME));

			final Map<String, String> scopesMap = new ObjectMapper()
					.readValue(parsedSet.getClaims().get("scopes").toString(), Map.class);

			String pispIntent = scopesMap.keySet().stream()
					.filter(item -> StringUtils.startsWithIgnoreCase(item, "PIS:")).findAny().orElse(null);
			String aispIntent = scopesMap.keySet().stream()
					.filter(item -> StringUtils.startsWithIgnoreCase(item, "AIS:")).findAny().orElse(null);
			List<String> scopesKey = scopesMap.keySet().stream().collect(Collectors.toList());

			log.debug("pispScope: {} ", pispIntent);
			log.debug("aispScope: {} ", aispIntent);

			model.addAttribute(SCOPES_LIST, scopesKey);

			final Map<String, String> fronClaimsMap = new ObjectMapper().readValue(
					parsedSet.getClaims().get(BerlingGroupConstants.IdTokenClaim.CLAIMS).toString(), Map.class);

			List<String> fronClaimsKey = fronClaimsMap.keySet().stream().collect(Collectors.toList());

			Claims claimsMap = Claims.parseClaims(getParsedClaim(parsedSet));
			model.addAttribute(BerlingGroupConstants.IdTokenClaim.CLAIMS, fronClaimsKey);
			log.debug("CONSENT_APPROVAL_REDIRECT_URI: {} ",
					parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));

			try {
				StringBuilder idmURL = new StringBuilder();
				if (!StringUtils.isEmpty(pispIntent)) {
					String[] pispArray = pispIntent.split(":");
					log.debug(" pispArray number of elements: {} ", pispArray.length);

					if (pispArray.length == 2) {
						idmURL = new StringBuilder().append(applicationProperties.getIdmGetPaymentIntentConsentUrl())
								.append(pispArray[1]);
						model.addAttribute("bgIntentId", pispArray[1]);
						// ===== PISP =====
						try {

							ResponseEntity<String> bgPaymentConsent = consentManagement
									.getOBPaymentConsent(idmURL.toString(),
											ReqestHeaders.builder()
													.username(applicationProperties.getIdmHeaderUsername())
													.password(applicationProperties.getIdmHeaderPassword()).build());
							BGPaymentConsentResponse bgPaymentConsentPISP = new GsonBuilder().create()
									.fromJson(bgPaymentConsent.getBody(), BGPaymentConsentResponse.class);
							if (bgPaymentConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
									.value()) {

								BGPaymentConsentResponse bgPaymentConsentPISPSendObject = consentUtils
										.completePaymentConsentResponseObject(bgPaymentConsentPISP);
								model.addAttribute("bgPaymentConsentPISP", bgPaymentConsentPISP);
								model.addAttribute("flow", BerlingGroupConstants.PISP.PISP_FLOW);

								// ObjectMapper mapper = new ObjectMapper();
								// JsonNode actualObj = mapper.readTree(bgPaymentConsent.getBody().toString());
								// String initiation = actualObj.get("Data").get("Initiation").toString();
								model.addAttribute("claims",
										new GsonBuilder().create().toJson(bgPaymentConsentPISPSendObject));
								if (bgPaymentConsentPISP != null && bgPaymentConsentPISP.getDebtorAccount() == null) {
									AllAccounts accountList = accountService.getAllAccounts(ReqestHeaders.builder()
											.username(applicationProperties.getIdmHeaderUsername())
											.password(applicationProperties.getIdmHeaderPassword()).build());

									if (accountList != null)
										model.addAttribute("accountList", accountList.getAccounts());
								}
							}
						} catch (Exception e) {
							log.error("Could not perform {} {}", BerlingGroupConstants.PISP.PISP_FLOW, e.getMessage());
						}
					}
				}
				if (!StringUtils.isEmpty(aispIntent)) {
					String[] aispArray = aispIntent.split(":");
					log.debug(" pispArray number of elements: {} ", aispArray.length);
					if (aispArray.length == 2) {
						idmURL = new StringBuilder().append(applicationProperties.getIdmGetAccountIntentConsentUrl())
								.append(aispArray[1]);
						model.addAttribute("bgIntentId", aispArray[1]);
						// ===== AISP =====
						try {
							AllAccounts accountList = accountService.getAllAccounts(
									ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
											.password(applicationProperties.getIdmHeaderPassword()).build());
							ResponseEntity<String> bgAccountConsent = consentManagement
									.getOBPaymentConsent(idmURL.toString(),
											ReqestHeaders.builder()
													.username(applicationProperties.getIdmHeaderUsername())
													.password(applicationProperties.getIdmHeaderPassword()).build());
							log.debug("AISP body: {} ", bgAccountConsent.getBody());
							BGAccountsAccessConsentResponse bgPaymentConsentAISP = new GsonBuilder().create()
									.fromJson(bgAccountConsent.getBody(), BGAccountsAccessConsentResponse.class);
							if (bgAccountConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
									.value()) {
								if (bgPaymentConsentAISP.getAccess().getAllPsd2() == null) {
									Access listOfABT = consentManagement
											.getListOfAccountsBalancesTransaction(bgPaymentConsentAISP, accountList);
									model.addAttribute("listOfABT", listOfABT);
									log.debug("listOfABT: {}" + listOfABT);
								}
								model.addAttribute("bgAccountsAccessConsentAIPS", bgPaymentConsentAISP);
								model.addAttribute("flow", BerlingGroupConstants.AISP.AISP_FLOW);

								if (accountList != null)
									model.addAttribute("accountList", accountList.getAccounts());

								ObjectMapper mapper = new ObjectMapper();
								JsonNode actualObj = mapper.readTree(bgAccountConsent.getBody().toString());
								String access = actualObj.toString();
								model.addAttribute("claims", access);
							}
						} catch (Exception e) {
							log.error("Could not perform {} {} ", BerlingGroupConstants.AISP.AISP_FLOW, e.getMessage());
						}
					}

				}
			} catch (Exception e) {
				log.error("Could not perform {} ", e.getMessage());
			}

		} catch (IOException | ParseException e) {
			log.error("Couldn't serialize response ", e);
		}

		return "consent_bg.html";
	}

	private JSONObject getParsedClaim(JWTClaimsSet parsedSet)
			throws IOException, JsonParseException, JsonMappingException, ParseException {
		return parsedSet.getJSONObjectClaim(BerlingGroupConstants.IdTokenClaim.CLAIMS);
	}

	@PostMapping("/api/rcs/consent/sendconsent")
	public String sendConsnet(
			@NotNull @ApiParam(value = "Get Scope from AM", required = true) @Valid @RequestParam(value = "consent_request", required = true) String consentRequestJwt,
			Model model, @RequestParam(value = "scope", required = false) List<String> scopes,
			@RequestParam(value = "account", required = false) List<String> accounts,
			@RequestParam(value = "balance", required = false) List<String> balances,
			@RequestParam(value = "transaction", required = false) List<String> transactions,
			@RequestParam(value = "decision", required = false) String reqestDecision,
			@RequestParam(value = "flow", required = false) String reqestFlow,
			@RequestParam(value = "claims", required = false) String claims,
			@RequestParam(value = "bgIntentId", required = false) String bgIntentId,
			@CookieValue(value = "${application.am-cookie-name}", required = false) String ssoToken) {
		try {
			log.debug("@CookieValue  {} ", ssoToken);
			log.debug("Consent body {} ", consentRequestJwt);
			log.debug("Consents prameter {} ", scopes);
			log.debug("Consents accounts {} ", accounts);
			log.debug("Consents balances {} ", balances);
			log.debug("Consents transactions {} ", transactions);
			log.debug("ReqestFlow {} ", reqestFlow);
			log.debug("claims {} ", claims);
			log.debug("bgIntentId {} ", bgIntentId);
			JWTClaimsSet parsedSet = setJwtClaims.parseJWT(consentRequestJwt);

			log.debug("Properties amJwkUrl {} ", applicationProperties.getAmJwkUrl());

			boolean decision = "allow".equalsIgnoreCase(reqestDecision);

			if (decision) {

				try {

					if (!StringUtils.isEmpty(bgIntentId)) {
						StringBuilder idmURL = new StringBuilder();
						String idmRequestBody = "";
						String sub = (String) parsedSet.getClaims().get(OIDCConstants.OIDCClaim.USERNAME);
						if (BerlingGroupConstants.PISP.PISP_FLOW.equals(reqestFlow)) {
							BGPaymentConsentResponse bgPaymentConsentPISPAfterConsent = new GsonBuilder().create()
									.fromJson(claims, BGPaymentConsentResponse.class);
							String choosedDebtorAccount=null;
							if (bgPaymentConsentPISPAfterConsent != null
									&& bgPaymentConsentPISPAfterConsent.getDebtorAccount() == null) {
								 choosedDebtorAccount = accounts != null && accounts.size() == 1 ? accounts.get(0) : "";
								bgPaymentConsentPISPAfterConsent.setDebtorAccount(DebtorAccount.builder()
										.iban(choosedDebtorAccount).build());
							}

							idmURL = new StringBuilder().append(applicationProperties.getIdmUpdatePaymentConsentUrl())
									.append(bgIntentId).append("?_action=patch");
							idmRequestBody = consentManagement.buildPispBody(sub,
									new GsonBuilder().create().toJson(bgPaymentConsentPISPAfterConsent),choosedDebtorAccount);

							PaymentConfirmationResponse paymentConfirmationResponse = paymentService
									.paymentConfirmation(PaymentConfirmationResquest.builder().consentId(bgIntentId)
											.transactionId(bgIntentId)
											.contDebit(bgPaymentConsentPISPAfterConsent.getDebtorAccount().getIban())
											.build());
							if (paymentConfirmationResponse != null) {
								log.info("paymentConfirmationResponse", paymentConfirmationResponse.toString());
							}

						} else if (BerlingGroupConstants.AISP.AISP_FLOW.equals(reqestFlow)) {							
							idmURL = new StringBuilder().append(applicationProperties.getIdmUpdateAccountConsentUrl())
									.append(bgIntentId).append("?_action=patch");
							idmRequestBody = consentManagement.buildAispBody(sub, accounts, balances, transactions,claims);
						}

						log.debug("url {}", idmURL);

						try {
							if (!StringUtils.isEmpty(idmURL)) {
								ResponseEntity<String> entity = consentManagement.updateOBPaymentConsent(
										idmURL.toString(),
										ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
												.password(applicationProperties.getIdmHeaderPassword()).build(),
										idmRequestBody);
							}
						} catch (Exception e) {
							log.error("Error on updateOBPaymentConsent: ", e.getMessage());
							throw new OBErrorException("Unable to updateOBPaymentConsent!");
						}

					}
				} catch (Exception e) {
					log.error("Could not perform {} " , e.getMessage());
				}
			}

			log.debug("decision {}  ", decision);

			String ecriptedJWT = (String) rcsService.generateRCSConsentResponse(applicationProperties,
					applicationProperties, (String) parsedSet.getClaims().get("csrf"), decision, scopes,
					(String) parsedSet.getClaims().get("clientId"), parsedSet);

			log.debug("get ecriptedJWT {}", ecriptedJWT);
			log.debug("REDIRECT_URI: {} ",
					parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));
			model.addAttribute("consent_response", ecriptedJWT);
			model.addAttribute("consent_response_field_name", "consent_response");
			model.addAttribute("redirect_uri",
					parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));

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