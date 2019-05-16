package com.forgerock.controller.accountAndTransaction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.forgerock.exceptions.ResourceNotFoundException;
import com.forgerock.service.accountAndTransaction.DirectDebitsService;

import uk.org.openbanking.datamodel.account.OBReadDirectDebit1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class DirectDebitsController {

	private static final Logger log = LoggerFactory.getLogger(DirectDebitsController.class);	

	/**
	 * Get all directDebits.
	 *
	 * @return the OBReadDirectDebit1 with list of directDebits
	 * @throws Exception
	 */
	@GetMapping(path = "/direct-debits", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadDirectDebit1> getDirectDebits() throws Exception {
		OBReadDirectDebit1 response = DirectDebitsService.getInstance().getDirectDebits();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get directDebits by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadDirectDebit1 with directDebits by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/direct-debits", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadDirectDebit1> getDirectDebitsByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadDirectDebit1 response = DirectDebitsService.getInstance().getDirectDebitsByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
