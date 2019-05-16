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
import com.forgerock.service.accountAndTransaction.TransactionsService;

import uk.org.openbanking.datamodel.account.OBReadTransaction4;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class TransactionsController {

	private static final Logger log = LoggerFactory.getLogger(TransactionsController.class);	

	/**
	 * Get all transactions.
	 *
	 * @return the OBReadTransaction4 with list of transactions
	 * @throws Exception
	 */
	@GetMapping(path = "/transactions", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadTransaction4> getTransactions() throws Exception {
		OBReadTransaction4 response = TransactionsService.getInstance().getTransactions();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get transaction by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadTransaction4 with transaction by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/transactions", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadTransaction4> getTransactionsByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadTransaction4 response = TransactionsService.getInstance().getTransactionsByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
