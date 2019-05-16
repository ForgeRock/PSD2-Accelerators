package com.forgerock.controller.fundsConfirmation;

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
import com.forgerock.service.fundsConfirmation.FundsConfirmationConsentService;

import uk.org.openbanking.datamodel.fund.OBFundsConfirmationConsent1;
import uk.org.openbanking.datamodel.fund.OBFundsConfirmationConsentResponse1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/funds-confirmation-consents")
public class FundsConfirmationConsentController {

	private static final Logger log = LoggerFactory.getLogger(FundsConfirmationConsentController.class);	

	
	@PostMapping(path = "/", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBFundsConfirmationConsentResponse1> createFundsConfirmationConsent(@RequestBody OBFundsConfirmationConsent1 fundsConfirmationConsent1) {
		OBFundsConfirmationConsentResponse1 response = FundsConfirmationConsentService.getInstance().createFundsConfirmationConsent(fundsConfirmationConsent1);
		return ResponseEntity.ok().body(response);
	}
	
	
	/**
	 * Get funds-confirmation-consents by consent id.
	 *
	 * @param id
	 *            the consent id
	 * @return the OBFundsConfirmationConsentResponse1 with funds-confirmation-consents by consent id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/{id}", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBFundsConfirmationConsentResponse1> getFundsConfirmationConsentByConsentId(@PathVariable(value = "id") String consentId) throws ResourceNotFoundException {
		OBFundsConfirmationConsentResponse1 response = FundsConfirmationConsentService.getInstance().getFundsConfirmationConsentByConsentId(consentId);
		return ResponseEntity.ok().body(response);
	}
	
	
	/**
	 * Delete funds-confirmation-consents map.
	 *
	 * @param id
	 *            the consent id
	 * @return the map
	 * @throws Exception
	 *             the exception
	 */
	@DeleteMapping("/{id}")
	public Map<String, Boolean> deleteFundsConfirmationConsentByConsentId(@PathVariable(value = "id") String consentId) throws Exception {
		FundsConfirmationConsentService.getInstance().deleteFundsConfirmationConsentByConsentId(consentId);
//		OBReadConsentResponse1DataService.getInstance().deleteConsent(id);
		Map<String, Boolean> response = new HashMap<>();
		response.put("deleted", Boolean.TRUE);
		return response;
	}

}
