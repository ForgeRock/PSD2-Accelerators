package com.forgerock.controller.accountAndTransaction;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.forgerock.exceptions.ResourceNotFoundException;
import com.forgerock.service.accountAndTransaction.AccountAccessConsentsService;

import uk.org.openbanking.datamodel.account.OBReadConsent1;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/account-access-consents")
public class AccountAccessConsentsController {

	private static final Logger log = LoggerFactory.getLogger(AccountAccessConsentsController.class);

	
	@PostMapping(path = "/", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadConsentResponse1> createConsent(@RequestBody OBReadConsent1 obReadConsent1) {
		OBReadConsentResponse1 response = AccountAccessConsentsService.getInstance().createConsent(obReadConsent1);
		return ResponseEntity.ok().body(response);
	}
	

	/**
	 * Get consent by id.
	 *
	 * @param id
	 *            the consent id
	 * @return the OBReadConsentResponse1 with consent by id
	 * @throws ResourceNotFoundException
	 *             the resource not found exception
	 */	
	@GetMapping(path = "/{id}", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadConsentResponse1> getConsentById(@PathVariable(value = "id") String consentId) throws ResourceNotFoundException {
		OBReadConsentResponse1 response = AccountAccessConsentsService.getInstance().getConsentById(consentId);
		return ResponseEntity.ok().body(response);
	}

	/**
	 * Delete user map.
	 *
	 * @param id
	 *            the consent id
	 * @return the map
	 * @throws Exception
	 *             the exception
	 */
	@DeleteMapping("/{id}")
	public Map<String, Boolean> deleteConsentById(@PathVariable(value = "id") String consentId) {
		AccountAccessConsentsService.getInstance().deleteConsentById(consentId);
		Map<String, Boolean> response = new HashMap<>();
		response.put("deleted", Boolean.TRUE);
		return response;
	}

}
