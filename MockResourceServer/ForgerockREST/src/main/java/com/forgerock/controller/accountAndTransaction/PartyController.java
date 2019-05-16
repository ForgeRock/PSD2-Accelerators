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
import com.forgerock.service.accountAndTransaction.PartyService;

import uk.org.openbanking.datamodel.account.OBReadParty1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class PartyController {

	private static final Logger log = LoggerFactory.getLogger(PartyController.class);	

	/**
	 * Get all Party.
	 *
	 * @return the OBReadParty1 with list of Party
	 * @throws Exception
	 */
	@GetMapping(path = "/party", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadParty1> getParty() throws Exception {
		OBReadParty1 response = PartyService.getInstance().getParty();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get Party by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadParty1 with Party by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/party", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadParty1> getPartyByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadParty1 response = PartyService.getInstance().getPartyByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
