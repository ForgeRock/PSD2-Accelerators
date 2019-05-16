package com.forgerock.controller.payment;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.forgerock.exceptions.ResourceNotFoundException;
import com.forgerock.service.payment.DiscoveryApiLinksService;
import com.forgerock.service.payment.DomesticPaymentsService;
import com.forgerock.pojo.DiscoveryApiLinksResponse;
import com.forgerock.pojo.DiscoveryApiLinksData;

import uk.org.openbanking.datamodel.discovery.OBDiscoveryAPILinksAccount3;
import uk.org.openbanking.datamodel.discovery.OBDiscoveryAPILinksPayment4;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticResponse2;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/obRSDiscovery")
public class DiscoveryApiLinksController {

	private static final Logger log = LoggerFactory.getLogger(DiscoveryApiLinksController.class);	

	
	/**
	 * Get Api Links by financial id.
	 *
	 * @param id
	 *            the financial id
	 * @return the DiscoveryApiLinksResponse with Api Links by financial id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/{id}", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<DiscoveryApiLinksResponse> getDiscoveryApiLinksById(@PathVariable(value = "id") String financialId) throws ResourceNotFoundException {
		DiscoveryApiLinksResponse response  =  DiscoveryApiLinksService.getInstance().getDiscoveryApiLinksResponseById(financialId);
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get Api Links by financial id.
	 *
	 * @param id
	 *            the financial id
	 * @return the DiscoveryApiLinksResponse with Api Links by financial id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<DiscoveryApiLinksResponse> getDefaultDiscoveryApiLinks() throws ResourceNotFoundException {
		
		DiscoveryApiLinksResponse response = null;
		try {
			response = DiscoveryApiLinksService.getInstance().getDiscoveryApiLinksResponseById("0015800001041REAAY");
		} catch (ResourceNotFoundException rnfe) {
			DiscoveryApiLinksData data = DiscoveryApiLinksService.getInstance().getDefaultData();
			response = DiscoveryApiLinksService.getInstance().createDiscoveryApiLinks(data);
		}

		return ResponseEntity.ok().body(response);
	}

}
