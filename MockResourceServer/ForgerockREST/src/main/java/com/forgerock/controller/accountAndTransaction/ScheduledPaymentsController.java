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
import com.forgerock.service.accountAndTransaction.ScheduledPaymentsService;

import uk.org.openbanking.datamodel.account.OBReadScheduledPayment1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class ScheduledPaymentsController {

	private static final Logger log = LoggerFactory.getLogger(ScheduledPaymentsController.class);	

	/**
	 * Get all scheduled-payments.
	 *
	 * @return the OBReadScheduledPayment1 with list of scheduled-payments
	 * @throws Exception
	 */
	@GetMapping(path = "/scheduled-payments", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadScheduledPayment1> getScheduledPayments() throws Exception {
		OBReadScheduledPayment1 response = ScheduledPaymentsService.getInstance().getScheduledPayments();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get scheduled-payments by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadScheduledPayment1 with scheduled-payments by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/scheduled-payments", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadScheduledPayment1> getScheduledPaymentsByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadScheduledPayment1 response = ScheduledPaymentsService.getInstance().getScheduledPaymentsByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
