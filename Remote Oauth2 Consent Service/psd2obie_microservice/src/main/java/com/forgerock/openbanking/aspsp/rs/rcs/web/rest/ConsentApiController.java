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
package com.forgerock.openbanking.aspsp.rs.rcs.web.rest;


import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OIDCConstants;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OIDCConstants.OIDCClaim;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants.AMRegistrationResponseClaims;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants.InternRCS;
import com.forgerock.openbanking.aspsp.rs.rcs.exceptions.OBErrorException;
import com.forgerock.openbanking.aspsp.rs.rcs.model.claims.Claim;
import com.forgerock.openbanking.aspsp.rs.rcs.model.claims.Claims;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ConsentRequest;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ConsentResponse;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ErrorDetails;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.OBPaymentConsentResponse;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.Account;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.domestic_payment.PaymentOrderConsentResponsePayload;
import com.forgerock.openbanking.aspsp.rs.rcs.model.rcs.RedirectionAction;
import com.forgerock.openbanking.aspsp.rs.rcs.service.AMAuthentificationService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.RcsService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.account.AccountService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.consent.ConsentManagement;
import com.forgerock.openbanking.aspsp.rs.rcs.service.jwt.JWTManagementService;
import com.forgerock.openbanking.aspsp.rs.rcs.service.keygenerator.IGenerateKey;
import com.forgerock.openbanking.aspsp.rs.rcs.service.parsing.ParseJWT;
import com.forgerock.openbanking.aspsp.rs.rcs.web.rest.errors.ErrorMessage;
import com.forgerock.openbanking.aspsp.rs.rcs.web.rest.util.ConversionUtils;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import io.swagger.annotations.ApiParam;
import net.minidev.json.JSONObject;
@javax.annotation.Generated(value = "io.swagger.codegen.languages.SpringCodegen", date = "2019-01-24T23:01:14.780Z")

@Controller
public class ConsentApiController implements ConsentApi {

    private static final Logger log = LoggerFactory.getLogger(ConsentApiController.class);

    private final ObjectMapper objectMapper;

    private final HttpServletRequest request;
    
    @Autowired
    IGenerateKey generatedKey;     
    @Autowired
    RcsService rcsService;    
    @Autowired
    JWTManagementService jwtManagementService;    
    @Autowired
    ParseJWT setJwtClaims;     
    @Autowired
    ApplicationProperties applicationProperties;
	@Autowired
	ConsentManagement consentManagement;
	@Autowired
	AMAuthentificationService amAuthentificationService;
	@Autowired 
	AccountService accountService;
        

    private static String jwkPub;
    @org.springframework.beans.factory.annotation.Autowired
    public ConsentApiController(ObjectMapper objectMapper, HttpServletRequest request) {
        this.objectMapper = objectMapper;
        this.request = request;
    }

    public ResponseEntity<String> apiConsentJwkPubGet() {        
      
            try {       
            	if(jwkPub==null) {            		
            		jwkPub =new StringBuilder()
            				.append("{\"keys\":[")
            				.append(jwtManagementService.senderSignKey().toPublicJWK().toJSONString())
            				.append(",")
            				.append(jwtManagementService.senderEncryptionKey().toPublicJWK().toJSONString())
            				.append("]}")
            				.toString();
            	}
            	log.debug("ConsentApiController senderKey(): {}", jwkPub);
                return new ResponseEntity<String>(jwkPub, HttpStatus.OK);
            } catch (NoSuchAlgorithmException | JOSEException | IOException | ParseException e) {
                log.error("Couldn't serialize response for content type application/json", e);
                return new ResponseEntity<String>(HttpStatus.INTERNAL_SERVER_ERROR);
            }
    }
    
    public ResponseEntity<ConsentResponse> getAMConsent(@NotNull @ApiParam(value = "Get Scope from AM", required = true) @Valid @RequestParam(value = "consent_request", required = true) String consentRequest) throws Exception {
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("application/json")) {
            try {
            	ConsentResponse consentResponse= new ConsentResponse(); 
            	log.debug("consent_request: {} ", consentRequest);       		
        		
        		try {
        			JWTClaimsSet parsedSet = setJwtClaims.parseJWT(consentRequest);
					consentResponse.setConsentRequest(consentRequest);
        			consentResponse.setConsentRequestFieldName("consent_request");

        			final Map<String, String> authInfo = new ObjectMapper().readValue(parsedSet.toString(), Map.class);

        			log.debug("authInfo: {} ", authInfo.toString());
        			log.debug("scopesList: {} ", authInfo.get("scopes"));
        			log.debug("parsedSet.getClaims(): {} ", parsedSet.getClaims().get("scopes"));

        			consentResponse.setClientName((String) parsedSet.getClaims().get(InternRCS.CLIENT_NAME));
        			consentResponse.setState((String) parsedSet.getClaims().get(OIDCClaim.STATE));
        			consentResponse.setUsername((String)parsedSet.getClaims().get(InternRCS.USERNAME));
        			String clientID =(String)parsedSet.getClaims().get(InternRCS.CLIENT_ID);
        			log.debug("Client ID {}",clientID);

        			final Map<String, String> scopesMap = new ObjectMapper()
        					.readValue(parsedSet.getClaims().get("scopes").toString(), Map.class);

        			List<String> scopesKey = scopesMap.keySet().stream().collect(Collectors.toList());

        			log.debug("scopesKey: {} ", scopesKey);
        			consentResponse.setScopeList(scopesKey);        			

        			final Map<String, String> fromClaimsMap = new ObjectMapper().readValue(
        					parsedSet.getClaims().get(OpenBankingConstants.IdTokenClaim.CLAIMS).toString(), Map.class);

        			List<String> fromClaimsKey = fromClaimsMap.keySet().stream().collect(Collectors.toList());

        			Claims claimsMap = Claims.parseClaims(getParsedClaim(parsedSet));
        			
        			consentResponse.setClaims(fromClaimsKey);
        			log.debug("CONSENT_APPROVAL_REDIRECT_URI: {} ",
        					parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));

        			String consentID = null;
        			try {
        				Claim instentId = claimsMap.getIdTokenClaims().get(OpenBankingConstants.IdTokenClaim.INTENT_ID);

        				log.debug("claimsMap.getAllClaims {} ", claimsMap.getAllClaims().toString());        				
        				log.debug("claim.getValues() {} ", instentId.getValue().toString());

        				consentID = instentId.getValue();
        				log.debug("consentID {}", consentID);
        				if (!StringUtils.isEmpty(consentID)) {
        					List<Account> accountList=accountService.getAllAccounts(ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
        										.password(applicationProperties.getIdmHeaderPassword()).build());
        					StringBuilder idmURL = new StringBuilder()
        							.append(applicationProperties.getIdmGetPaymentIntentConsentUrl()).append(consentID)
        							.append("?_fields=*,Tpp/*");

        					// ===== PISP =====
        					try {
        						ResponseEntity<String> obPaymentConsent = consentManagement.getOBPaymentConsent(
        								idmURL.toString(),
        								ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
        										.password(applicationProperties.getIdmHeaderPassword()).build());
        						PaymentOrderConsentResponsePayload obPaymentConsentPISP = new GsonBuilder().create()
        								.fromJson(obPaymentConsent.getBody(), PaymentOrderConsentResponsePayload.class);
        						if (obPaymentConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
        								.value()) {
        							
        							ConsentResponse errorConsentResponse= new ConsentResponse();
        							if(!isTPPMatching(clientID,obPaymentConsentPISP)) {
        								errorConsentResponse.setErrorDetails(ErrorDetails.builder().errorId("ERR005").errorMessage(ErrorMessage.ERR005.getMessage()).build());
    									return new ResponseEntity<ConsentResponse>(errorConsentResponse, HttpStatus.OK);
        							}
        							
        							if(!applicationProperties.getIdmConsentStatusAwaiting().equalsIgnoreCase( obPaymentConsentPISP.getData().getStatus())) {  
        								        								
        							    									 
    									errorConsentResponse.setErrorDetails(
    											ErrorDetails.builder().
    											errorId("ERR003").
    											errorMessage(String.format( ErrorMessage.ERR003.getMessage(),applicationProperties.getIdmConsentStatusAwaiting()))
    											.build());
    									return new ResponseEntity<ConsentResponse>(errorConsentResponse, HttpStatus.OK);
        									       								
        							}
        							consentResponse.setObPaymentConsentPISP(obPaymentConsentPISP);       							
        							consentResponse.setFlow(OpenBankingConstants.PISP.PISP_FLOW);
        							
        							if(accountList!=null)consentResponse.setAccountList(accountList); 

        							ObjectMapper mapper = new ObjectMapper();
        							JsonNode actualObj = mapper.readTree(obPaymentConsent.getBody().toString());
        							String initiation = actualObj.get("Data").get("Initiation").toString();
        							consentResponse.setInitiationClaims((String)initiation);
        							
        						}
        					} catch (Exception e) {
        						log.error("Could not perform {} ", OpenBankingConstants.PISP.PISP_FLOW, e.getMessage());        						
        					}

        					idmURL = new StringBuilder().append(applicationProperties.getIdmGetAccountIntentConsentUrl())
        							.append(consentID).append("?_fields=*,Tpp/*");

        					// ===== AISP =====
        					try {
        						ResponseEntity<String> obAccountConsent = consentManagement.getOBPaymentConsent(
        								idmURL.toString(),
        								ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
        										.password(applicationProperties.getIdmHeaderPassword()).build());
        						log.debug("AISP body: " + obAccountConsent.getBody());
        						OBPaymentConsentResponse obAccountConsentAISP = new GsonBuilder().create()
        								.fromJson(obAccountConsent.getBody(), OBPaymentConsentResponse.class);
        						if (obAccountConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
        								.value()) {
        							ConsentResponse errorConsentResponse= new ConsentResponse();
        							
        							if(!isTPPMatching(clientID,obAccountConsentAISP)) {
        								errorConsentResponse.setErrorDetails(ErrorDetails.builder().errorId("ERR005").errorMessage(ErrorMessage.ERR005.getMessage()).build());
    									return new ResponseEntity<ConsentResponse>(errorConsentResponse, HttpStatus.OK);
        							}
        							
        							if(applicationProperties.getIdmConsentStatusAuthorised().equalsIgnoreCase( obAccountConsentAISP.getData().getStatus())) {  
        								
        								obAccountConsentAISP.getData().getCreationDateTime();
        								boolean isAuthorisedNotExpired= ConversionUtils.isTimeExpired(obAccountConsentAISP.getData().getStatusUpdateDateTime(), applicationProperties.getScaTimeAutoAccept(), OpenBankingConstants.OpenIDM.IDM_DATE_FORMAT, Calendar.DATE);
        								//applicationProperties.getScaTimeExpire()
        								boolean isAuthorisedAndExpired = ConversionUtils.isTimeExpired(obAccountConsentAISP.getData().getCreationDateTime(), applicationProperties.getScaTimeExpire(), OpenBankingConstants.OpenIDM.IDM_DATE_FORMAT, Calendar.DATE); 
        								log.debug("isAuthorisedNotExpired: {} after {} day ", isAuthorisedNotExpired,applicationProperties.getScaTimeAutoAccept());
        								
        								if(isAuthorisedNotExpired&&!isAuthorisedAndExpired) {
        									consentResponse.setFlow(OpenBankingConstants.AISP.AISP_FLOW_AUTO_ACCEPT);
        									 return new ResponseEntity<ConsentResponse>(consentResponse, HttpStatus.OK);
        								}
        								log.debug("isAuthorisedAndExpired: {} afer {} day", isAuthorisedNotExpired,applicationProperties.getScaTimeExpire());
        								if(isAuthorisedAndExpired) {        									 
        									errorConsentResponse.setErrorDetails(ErrorDetails.builder().errorId("ERR001").errorMessage(ErrorMessage.ERR001.getMessage()).build());
        									return new ResponseEntity<ConsentResponse>(errorConsentResponse, HttpStatus.OK);
        								}  
        								errorConsentResponse.setErrorDetails(ErrorDetails.builder().errorId("ERR004").errorMessage(ErrorMessage.ERR004.getMessage()).build());
    									return new ResponseEntity<ConsentResponse>(errorConsentResponse, HttpStatus.OK);
        							}
        							
        							if(!applicationProperties.getIdmConsentStatusAwaiting().equalsIgnoreCase( obAccountConsentAISP.getData().getStatus())) {  
        							     		        							    									 
    									errorConsentResponse.setErrorDetails(
    											ErrorDetails.builder().
    											errorId("ERR002").
    											errorMessage(String.format( ErrorMessage.ERR002.getMessage(),applicationProperties.getIdmConsentStatusAwaiting()))
    											.build());
    									return new ResponseEntity<ConsentResponse>(errorConsentResponse, HttpStatus.OK);
        									       								
        							}
        							consentResponse.setObAccountsAccessConsentAIPS(obAccountConsentAISP);
        							
        							consentResponse.setFlow(OpenBankingConstants.AISP.AISP_FLOW);
        							if(accountList!=null)consentResponse.setAccountList(accountList); 

        							ObjectMapper mapper = new ObjectMapper();
        							JsonNode actualObj = mapper.readTree(obAccountConsent.getBody().toString());
        							String permissions = actualObj.get("Data").get("Permissions").toString();
        							consentResponse.setInitiationClaims(permissions);  
        							
        							
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
        		 
                return new ResponseEntity<ConsentResponse>(consentResponse, HttpStatus.OK);
            } catch (IOException e) {
                log.error("Couldn't serialize response for content type application/json", e);
                return new ResponseEntity<ConsentResponse>(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }

        return new ResponseEntity<ConsentResponse>(HttpStatus.NOT_IMPLEMENTED);
    }
	private boolean isTPPMatching(String clientID, Object idmResponse) {
		try{
			if(idmResponse instanceof PaymentOrderConsentResponsePayload) {
				if(clientID.equalsIgnoreCase(((PaymentOrderConsentResponsePayload) idmResponse).getTpp().getIdentifier())) {
					return true;
				}
			}
			if(idmResponse instanceof OBPaymentConsentResponse) {
				if(clientID.equalsIgnoreCase(((OBPaymentConsentResponse) idmResponse).getTpp().getIdentifier())) {
					return true;
				}
			}
		}
		catch (Exception e) {
			log.error("Couldn't get Identifier from TPP or Client Id is Null :",e);			
		}
		return false;
	}

	private JSONObject getParsedClaim(JWTClaimsSet parsedSet)
			throws IOException, JsonParseException, JsonMappingException, ParseException {
		return parsedSet.getJSONObjectClaim(OpenBankingConstants.IdTokenClaim.CLAIMS);
	}

    public ResponseEntity<RedirectionAction> sendConsent(@ApiParam(value = "Consnet Request Object" ,required=true )  @Valid @RequestBody ConsentRequest consentRequest,
    @CookieValue(value = "${application.am-cookie-name}", required = false) String ssoToken) {
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("application/json")) {
            try {
            	log.debug("@CookieValue  {} ", ssoToken);
    			log.debug("Consent body {} ", consentRequest.getConsentRequest());
    			log.debug("Consents prameter {} ", consentRequest.getScope());
    			log.debug("Consents accounts {} ", consentRequest.getAccount());
    			log.debug("ReqestFlow {} ", consentRequest.getFlow());
    			log.debug("claims {} ", consentRequest.getClaims());
    			JWTClaimsSet parsedSet = setJwtClaims.parseJWT(consentRequest.getConsentRequest());

    			log.debug("Properties amJwkUrl {} ", applicationProperties.getAmJwkUrl());

    			boolean decision = "allow".equalsIgnoreCase(consentRequest.getDecision());
    			
				Claims claimsMap = Claims.parseClaims(getParsedClaim(parsedSet));
				String consentID = null;
				try {
					Claim instentId = claimsMap.getIdTokenClaims().get(OpenBankingConstants.IdTokenClaim.INTENT_ID);

					log.debug("claimsMap {} ", claimsMap.toString());					
					log.debug("claim.getValues() {} ", instentId.getValue().toString());

					consentID = instentId.getValue();

					if (!StringUtils.isEmpty(consentID)) {
						StringBuilder idmURL = new StringBuilder();
						String idmRequestBody = "";
						HttpMethod methodForUpdate = HttpMethod.POST;
						String sub = (String) parsedSet.getClaims().get(OIDCConstants.OIDCClaim.USERNAME);
						if (OpenBankingConstants.PISP.PISP_FLOW.equals(consentRequest.getFlow())) {
							idmURL = new StringBuilder().append(applicationProperties.getIdmUpdatePaymentConsentUrl())
									.append(consentID).append("?_action=patch");
							
							idmRequestBody = consentManagement.buildPispBody(sub, consentRequest.getClaims(),consentRequest.getAccount(),decision);
							callForUpdateObjectInIDM(idmURL, idmRequestBody, methodForUpdate);
						} else if (OpenBankingConstants.AISP.AISP_FLOW.equals(consentRequest.getFlow())) {
							idmURL = new StringBuilder().append(applicationProperties.getIdmUpdateAccountConsentUrl())
									.append(consentID).append("?_action=patch");
							idmRequestBody = consentManagement.buildAispBody(sub, consentRequest.getClaims(), consentRequest.getAccount(),decision);
							callForUpdateObjectInIDM(idmURL, idmRequestBody, methodForUpdate);
						}
						else if (OpenBankingConstants.AISP.AISP_FLOW_AUTO_ACCEPT.equals(consentRequest.getFlow())) {
							decision=true;
							log.info("AISP Auto Accept Flow, make decision auto true");
							idmURL = new StringBuilder().append(applicationProperties.getIdmGetAccountIntentConsentUrl())
									.append(consentID);
							idmRequestBody = consentManagement.buildAispAutoAcceptBody();
							methodForUpdate = HttpMethod.POST;
							callForPatchObjectInIDM(idmURL, idmRequestBody, methodForUpdate);
						}
						
						
					}
				} catch (Exception e) {
					log.error("Could not obtain " + OpenBankingConstants.IdTokenClaim.INTENT_ID, e.getMessage());
				}
    			

    			log.debug("decision {}  ", decision);

    			JWTClaimsSet claimsSet= rcsService.generateRCSConsentResponse(applicationProperties,
    					applicationProperties, (String) parsedSet.getClaims().get("csrf"), decision, consentRequest.getScope(),
    					(String) parsedSet.getClaims().get("clientId"), parsedSet);
    			String signedJWT =jwtManagementService.senderSignJWT(claimsSet.toJSONObject().toString(), applicationProperties);			
    			log.debug("get signedJWT {}", signedJWT);
    			
    			//String ecriptedJWT = jwtManagementService.senderSignEncryptJWT( applicationProperties, claimsSet.toJSONObject().toString());
    			//log.debug("get ecriptedJWT {}", ecriptedJWT);
    			log.debug("REDIRECT_URI: {} ",
    					parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));
    			//model.addAttribute("consent_response", signedJWT);
    			//model.addAttribute("consent_response_field_name", "consent_response");
    			//model.addAttribute("redirect_uri",
    			//		parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI));

    			return ResponseEntity.ok(RedirectionAction.builder()
	                    .redirectUri(
	                    			StringUtils.replace(parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI), "null://null/openam", applicationProperties.getAmHostUrl())
	                    		)
	                    .consentJwt(signedJWT)
	                    .build());    	
    			//ResponseEntity responseEntity =consentManagement.redirectToAM(signedJWT,parsedSet.getStringClaim(OIDCConstants.OIDCClaim.CONSENT_APPROVAL_REDIRECT_URI),ssoToken,applicationProperties);
    			
    			// Return to AM
    			 //if (responseEntity.getStatusCode() != HttpStatus.FOUND) {
    	       //         log.error("When sending the consent response {} to AM, it failed to returned a 302", signedJWT, responseEntity);
    	          //      throw new OBErrorException("RCS Consent fail");
    	           // }

    	           // String location = responseEntity.getHeaders().getFirst(HttpHeaders.LOCATION);
    	           // log.debug("The redirection to the consent page should be in the location '{}'", location);

    	            //return ResponseEntity.ok(RedirectionAction.builder()
    	              //      .redirectUri(location)
    	               //     .build()); 
    	            
    	            

                //return new ResponseEntity<Empty>(objectMapper.readValue("{ }", Empty.class), HttpStatus.FOUND);
            } catch (Exception e) {
                log.error("Couldn't serialize response for content type application/json", e);
                return new ResponseEntity<RedirectionAction>(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }

        return new ResponseEntity<RedirectionAction>(HttpStatus.NOT_IMPLEMENTED);
    }

	private void callForUpdateObjectInIDM(StringBuilder idmURL, String idmRequestBody, HttpMethod methodForUpdate)
			throws OBErrorException {
		log.debug("url {}", idmURL);
		try {
			if (!StringUtils.isEmpty(idmURL.toString())) {
				ResponseEntity<String> entity = consentManagement.updateOBPaymentConsent(
						idmURL.toString(),
						ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
								.password(applicationProperties.getIdmHeaderPassword()).build(),
						idmRequestBody,methodForUpdate);
			}
		} catch (Exception e) {
			log.error("Error on updateOBPaymentConsent: ", e.getMessage());
			throw new OBErrorException("Unable to updateOBPaymentConsent!");
		}
	}
	private void callForPatchObjectInIDM(StringBuilder idmURL, String idmRequestBody, HttpMethod methodForUpdate)
			throws OBErrorException {
		log.debug("url {}", idmURL);
		try {
			if (!StringUtils.isEmpty(idmURL.toString())) {
				ResponseEntity<String> entity = consentManagement.updateOBPaymentConsentPatch(
						idmURL.toString(),
						ReqestHeaders.builder().username(applicationProperties.getIdmHeaderUsername())
								.password(applicationProperties.getIdmHeaderPassword()).build(),
						idmRequestBody,methodForUpdate);
			}
		} catch (Exception e) {
			log.error("Error on updateOBPaymentConsent: ", e.getMessage());
			throw new OBErrorException("Unable to updateOBPaymentConsent!");
		}
	}

}
