package com.forgerock.controller.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.exceptions.ResourceNotFoundException;
import com.forgerock.service.accountAndTransaction.AccountsService;
import com.forgerock.service.parsing.ParseJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import uk.org.openbanking.datamodel.account.OBReadAccount2;

@RestController
@RequestMapping(path = "/accounts")
public class AccountsController {

	@Autowired
	ParseJWT setJwtClaims;
	
	private static final Logger log = LoggerFactory.getLogger(AccountsController.class);	

	/**
	 * Get all accounts.
	 *
	 * @return the OBReadAccount2 with list of accounts
	 * @throws Exception
	 */
	@GetMapping(path = "/", produces = "application/json")
	public ResponseEntity<OBReadAccount2> getAccounts(@RequestParam(value = "accounts" , required = false) String accountsJwt) throws Exception {

		if (null == accountsJwt || accountsJwt.isEmpty()) {
			log.info("getAllAccounts ");
			OBReadAccount2 response = AccountsService.getInstance().getAccounts();
			return ResponseEntity.ok().body(response);
		}
		
		List<String> accounts = new ArrayList<>();
		String label = "accounts";
		Object obj = getDataFromJWT(accountsJwt, label);
		if (null != obj) {
			accounts = (List<String>) obj;
		} else {
			accounts.add("-1");
		}
		log.info("getAccountsByIds ");
		OBReadAccount2 response = AccountsService.getInstance().getAccountsByIds(accounts, accountsJwt);
		return ResponseEntity.ok().body(response);
	}

	
	/**
	 * Get account by id.
	 *
	 * @param id
	 *            the account id
	 * @return the OBReadAccount2 with account by id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/{id}", produces = "application/json")
	public ResponseEntity<OBReadAccount2> getAccountById(@PathVariable(value = "id") String accountId) throws ResourceNotFoundException {
		log.info("getAccountById ");
		OBReadAccount2 response = AccountsService.getInstance().getAccountById(accountId);
		return ResponseEntity.ok().body(response);
	}
	
	private Object getDataFromJWT(String jwt, String label) throws Exception {
		JWTClaimsSet parsedSet = null;
		Object result = null;
		try {
			parsedSet = setJwtClaims.parseJWT(jwt);
		} catch (Exception e) {
			throw new Exception("Cannot parse jwt!");
		}

		log.info("parsedSet = "+parsedSet);
		if (null != parsedSet) {
			final Map<String, String> jwtInfo = new ObjectMapper().readValue(parsedSet.toString(), Map.class);
			if (jwtInfo.keySet().contains(label)) {
				result = parsedSet.getClaims().get(label);
				log.info("Parsed result: ", result);
			} else {
				throw new Exception("The requested data cannot be extracted!");
			}
		}
		return result;
	}
}
