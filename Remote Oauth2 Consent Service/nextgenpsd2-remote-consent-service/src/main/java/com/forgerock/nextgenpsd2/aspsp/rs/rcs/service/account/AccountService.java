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
package com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.account;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.forgerock.nextgenpsd2.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.consent.bgpcr.AllAccounts;
import com.google.gson.GsonBuilder;

@Service
public class AccountService {
	private final static Logger log = LoggerFactory.getLogger(AccountService.class);


	@Autowired
	ApplicationProperties applicationProperties;
	
	public AllAccounts getAllAccounts( ReqestHeaders header){
		
		log.debug("url: {}", applicationProperties.getAccountsEndpoint());
		log.debug("idmHeader: {}", header);		
		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obPaymentConsent = restTemplate.exchange(applicationProperties.getAccountsEndpoint(), HttpMethod.GET,
				new HttpEntity<Object>(header), String.class);
		log.debug("obPaymentConsent StatusCode : {}", obPaymentConsent.getStatusCode());
		log.debug("obPaymentConsent getBody : {}", obPaymentConsent.getBody());
		AllAccounts getAllAccount = new GsonBuilder().create()
				.fromJson(obPaymentConsent.getBody(), AllAccounts.class);
		if (obPaymentConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
				.value()) {
			return getAllAccount;
		}
		return null;
	}
}
