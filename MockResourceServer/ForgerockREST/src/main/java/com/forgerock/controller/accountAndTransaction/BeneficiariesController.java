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
import com.forgerock.service.accountAndTransaction.BeneficiariesService;

import uk.org.openbanking.datamodel.account.OBReadBeneficiary2;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class BeneficiariesController {

	private static final Logger log = LoggerFactory.getLogger(BeneficiariesController.class);	

	/**
	 * Get all beneficiaries.
	 *
	 * @return the OBReadBeneficiary2 with list of beneficiaries
	 * @throws Exception
	 */
	@GetMapping(path = "/beneficiaries", produces = "application/json")
	public ResponseEntity<OBReadBeneficiary2> getBeneficiaries() throws Exception {
		OBReadBeneficiary2 response = BeneficiariesService.getInstance().getBeneficiaries();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get beneficiary by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadBeneficiary2 with beneficiary by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/beneficiaries", produces = "application/json")
	public ResponseEntity<OBReadBeneficiary2> getBeneficiaryByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadBeneficiary2 response = BeneficiariesService.getInstance().getBeneficiaryByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
