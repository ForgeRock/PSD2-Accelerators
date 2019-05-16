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
import com.forgerock.service.accountAndTransaction.OffersService;

import uk.org.openbanking.datamodel.account.OBReadOffer1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class OffersController {

	private static final Logger log = LoggerFactory.getLogger(OffersController.class);	

	/**
	 * Get all Offers.
	 *
	 * @return the OBReadOffer1 with list of Offers
	 * @throws Exception
	 */
	@GetMapping(path = "/offers", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadOffer1> getOffers() throws Exception {
		OBReadOffer1 response = OffersService.getInstance().getOffers();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get Offers by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadOffer1 with Offer by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/offers", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadOffer1> getOffersByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadOffer1 response = OffersService.getInstance().getOffersByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
