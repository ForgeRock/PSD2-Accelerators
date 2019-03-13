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
package com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.payment;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.forgerock.nextgenpsd2.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.payment.PaymentConfirmationResponse;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.payment.PaymentConfirmationResquest;
import com.google.gson.GsonBuilder;

@Service
public class PaymentService {
	private final static Logger log = LoggerFactory.getLogger(PaymentService.class);

	@Autowired
	ApplicationProperties applicationProperties;

	public PaymentConfirmationResponse paymentConfirmation(PaymentConfirmationResquest paymentConfirmationResquest) {
try {
		log.debug("url: {}", applicationProperties.getPaymentConfirmationEndpoint());
		String jsonBody = new GsonBuilder().create().toJson(paymentConfirmationResquest);
		log.debug("jsonBody: {}", jsonBody);

		HttpHeaders openIdmHeader = new HttpHeaders();
		openIdmHeader.add("Content-Type", "application/json");

		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<String> obPaymentConfirmation = restTemplate.exchange(
				applicationProperties.getPaymentConfirmationEndpoint(), HttpMethod.POST,
				new HttpEntity<Object>(jsonBody, openIdmHeader), String.class);
		log.debug("obPaymentConfirmation StatusCode : {}", obPaymentConfirmation.getStatusCode());
		log.debug("obPaymentConfirmation getBody : {}", obPaymentConfirmation.getBody());
		PaymentConfirmationResponse paymentConfirmationResponse = new GsonBuilder().create()
				.fromJson(obPaymentConfirmation.getBody(), PaymentConfirmationResponse.class);
		if (obPaymentConfirmation.getStatusCode().value() == org.springframework.http.HttpStatus.OK.value()) {
			return paymentConfirmationResponse;
		}
		
		} catch (Exception e) {
			log.error("Confirmation Payment error {}", e.getMessage());
		}
	return null;
	}
}
