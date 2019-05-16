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
import com.forgerock.service.accountAndTransaction.StandingOrdersService;

import uk.org.openbanking.datamodel.account.OBReadStandingOrder4;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class StandingOrdersController {

	private static final Logger log = LoggerFactory.getLogger(StandingOrdersController.class);	

	/**
	 * Get all Standing-orders.
	 *
	 * @return the OBReadStandingOrder4 with list of Standing-orders
	 * @throws Exception
	 */
	@GetMapping(path = "/standing-orders", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadStandingOrder4> getStandingOrders() throws Exception {
		OBReadStandingOrder4 response = StandingOrdersService.getInstance().getStandingOrders();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get Standing-orders by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadStandingOrder4 with Standing-orders by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/standing-orders", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadStandingOrder4> getStandingOrdersByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadStandingOrder4 response = StandingOrdersService.getInstance().getStandingOrdersByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
