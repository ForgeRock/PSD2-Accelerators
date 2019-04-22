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
package com.forgerock.openbanking.aspsp.rs.rcs.service;

import java.time.Duration;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.model.rcs.RedirectionAction;
import com.forgerock.openbanking.aspsp.rs.rcs.service.jwt.JWTManagementService;
import com.nimbusds.jwt.JWTClaimsSet;

@org.springframework.stereotype.Service
public class RcsService {
	private final static Logger log = LoggerFactory.getLogger(RcsService.class);
	@Autowired
	JWTManagementService jwtManagementService;

//	@Resource(name = "restTemplateForRCS")
//    private RestTemplate restTemplate;

//	@Value("${rcs.issuer-id}")
//    public String issuerId;
//    @Value("${am.cookie.name}")
//    private String cookieName;
	/**
	 * Generate a new RCS authentication JWT.
	 *
	 * @return a JWT that can be used to authenticate RCS to the AS.
	 * @throws Exception
	 */
	public JWTClaimsSet generateRCSConsentResponse(ApplicationProperties rcsConfiguration,
			ApplicationProperties amConfiguration, String csrf, boolean decision, List<String> scopes, String clientId,
			JWTClaimsSet jwtClaimsSet) throws Exception {
		JWTClaimsSet.Builder requestParameterClaims;
		requestParameterClaims = new JWTClaimsSet.Builder();

		requestParameterClaims.issuer(rcsConfiguration.getIssuerID());
		requestParameterClaims.audience(jwtClaimsSet.getIssuer());
		requestParameterClaims.expirationTime(new Date(new Date().getTime() + Duration.ofMinutes(5).toMillis()));
		requestParameterClaims.claim("save_consent_enabled", jwtClaimsSet.getClaims().get("save_consent_enabled"));
		requestParameterClaims.claim("csrf", csrf);
		requestParameterClaims.claim("scopes", scopes);
		requestParameterClaims.claim("clientId", clientId);

		requestParameterClaims.issueTime(jwtClaimsSet.getIssueTime());
		requestParameterClaims.claim("claims", jwtClaimsSet.getJSONObjectClaim("claims"));
		requestParameterClaims.claim("client_name", jwtClaimsSet.getClaim("client_name"));
		requestParameterClaims.claim("consentApprovalRedirectUri", jwtClaimsSet.getClaim("consentApprovalRedirectUri"));
		requestParameterClaims.claim("username", jwtClaimsSet.getClaim("username"));
		requestParameterClaims.claim("decision", decision);
		return requestParameterClaims.build();
	}

	
}
