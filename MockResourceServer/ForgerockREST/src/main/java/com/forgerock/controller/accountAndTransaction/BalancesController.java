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
import com.forgerock.service.accountAndTransaction.BalancesService;

import uk.org.openbanking.datamodel.account.OBReadBalance1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class BalancesController {

	private static final Logger log = LoggerFactory.getLogger(BalancesController.class);	

	/**
	 * Get all balances.
	 *
	 * @return the OBReadBalance1 with list of balances
	 * @throws Exception
	 */
	@GetMapping(path = "/balances", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadBalance1> getBalances() throws Exception {
		OBReadBalance1 response = BalancesService.getInstance().getBalances();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get balance by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadBalance1 with balance by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/balances", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadBalance1> getBalanceByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadBalance1 response = BalancesService.getInstance().getBalanceByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
