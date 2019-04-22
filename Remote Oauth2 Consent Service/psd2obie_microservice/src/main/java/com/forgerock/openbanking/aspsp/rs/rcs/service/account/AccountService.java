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
package com.forgerock.openbanking.aspsp.rs.rcs.service.account;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants.OpenIDM;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.OBPaymentConsentResponse;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.Account;
import com.forgerock.openbanking.aspsp.rs.rcs.service.consent.ConsentManagement;
import com.google.gson.GsonBuilder;

@Service
public class AccountService {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagement.class);


	@Autowired
	ApplicationProperties applicationProperties;
	
	public List<Account> getAllAccounts( ReqestHeaders header){
		
		log.debug("url: {}", applicationProperties.getAccountsEndpoint());
		log.debug("idmHeader: {}", header);		
		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obPaymentConsent = restTemplate.exchange(applicationProperties.getAccountsEndpoint(), HttpMethod.GET,
				new HttpEntity<Object>(header), String.class);
		log.debug("obPaymentConsent StatusCode : {}", obPaymentConsent.getStatusCode());
		log.debug("obPaymentConsent getBody : {}", obPaymentConsent.getBody());
		OBPaymentConsentResponse getAllAccount = new GsonBuilder().create()
				.fromJson(obPaymentConsent.getBody(), OBPaymentConsentResponse.class);
		if (obPaymentConsent.getStatusCode().value() == org.springframework.http.HttpStatus.OK
				.value()) {
			return getAllAccount.getData().getAccount();
		}
		return null;
	}
}
