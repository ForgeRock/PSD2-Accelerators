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
import com.forgerock.service.accountAndTransaction.ProductsService;

import uk.org.openbanking.datamodel.account.OBReadProduct2;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class ProductsController {

	private static final Logger log = LoggerFactory.getLogger(ProductsController.class);	

	/**
	 * Get all products.
	 *
	 * @return the OBReadProduct2 with list of products
	 * @throws Exception
	 */
	@GetMapping(path = "/products", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadProduct2> getProducts() throws Exception {
		OBReadProduct2 response = ProductsService.getInstance().getProducts();
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get product by account id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadProduct2 with product by account id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/accounts/{id}/product", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBReadProduct2> getProductByAccountId(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		OBReadProduct2 response = ProductsService.getInstance().getProductByAccountId(accountId);
		return ResponseEntity.ok().body(response);
	}
}
