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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants.OpenAM;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.RequestConsntToIDM;
import com.forgerock.openbanking.aspsp.rs.rcs.service.consent.ConsentManagement;

@Service
public class AMAuthentificationService {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagement.class);
	
	public ResponseEntity<String> postAMAuthentificatin(String url, ReqestHeaders header, List<RequestConsntToIDM> requestbodyToAM) {
		log.debug("url: {}",url);		
		log.debug("idmHeader: {}",header);
		log.debug("requestConsentToIDM: {}",requestbodyToAM);
		
		HttpHeaders openAMHeader = new HttpHeaders();       
        openAMHeader.add(OpenAM.X_OPENAM_USERNAME, header.getUsername());
        openAMHeader.add(OpenAM.X_OPENAM_PASSWORD, header.getPassword());
        openAMHeader.add("Content-Type", "application/json");
        openAMHeader.add("Accept-API-Version","resource=2.0, protocol=1.0");
       
		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obAMAuth = restTemplate.exchange(url,HttpMethod.POST, new HttpEntity<Object>(requestbodyToAM,openAMHeader),String.class);
		log.debug("obPaymentConsent StatusCode : {}",obAMAuth.getStatusCode());
		log.debug("obPaymentConsent getBody : {}",obAMAuth.getBody());
		log.debug("obPaymentConsent getBody : {}",obAMAuth.getHeaders().getFirst(HttpHeaders.SET_COOKIE));
		return obAMAuth;

	}
	
}
