package com.forgerock.controller.payment;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.forgerock.exceptions.ResourceNotFoundException;
import com.forgerock.service.payment.DomesticPaymentsService;

import uk.org.openbanking.datamodel.payment.OBWriteDomestic2;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsent2;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsentResponse2;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticResponse2;
import uk.org.openbanking.datamodel.payment.OBWriteFundsConfirmationResponse1;
import uk.org.openbanking.jackson.DateTimeDeserializer;

@RestController
@RequestMapping(path = "/")
public class DomesticPaymentsController {

	private static final Logger log = LoggerFactory.getLogger(DomesticPaymentsController.class);	

	
	@PostMapping(path = "/domestic-payment-consents", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBWriteDomesticConsentResponse2> createDomesticPaymentConsent(@RequestBody OBWriteDomesticConsent2 domesticConsent2) throws ResourceNotFoundException {
		OBWriteDomesticConsentResponse2 response = DomesticPaymentsService.getInstance().createDomesticPaymentConsent(domesticConsent2);
		return ResponseEntity.ok().body(response);
	}
	
	
	@PostMapping(path = "/domestic-payments", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBWriteDomesticResponse2> createDomesticPayment(@RequestBody OBWriteDomestic2 domestic2) throws ResourceNotFoundException {
		OBWriteDomesticResponse2 response = DomesticPaymentsService.getInstance().createDomesticPayment(domestic2);
		return ResponseEntity.ok().body(response);
	}
	
	
	/**
	 * Get payment-consents by consent id.
	 *
	 * @param id
	 *            the consent id
	 * @return the OBWriteDomesticConsentResponse2 with payment-consents by consent id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/domestic-payment-consents/{id}", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBWriteDomesticConsentResponse2> getDomesticPaymentConsentById(@PathVariable(value = "id") String consentId) throws ResourceNotFoundException {
		OBWriteDomesticConsentResponse2 response = DomesticPaymentsService.getInstance().getDomesticPaymentConsentById(consentId);
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get payment by payment id.
	 *
	 * @param id
	 *            the payment id
	 * @return the OBWriteDomesticResponse2 with payment by payment id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/domestic-payments/{id}", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBWriteDomesticResponse2> getDomesticPaymentById(@PathVariable(value = "id") String paymentId) throws ResourceNotFoundException {
		OBWriteDomesticResponse2 response = DomesticPaymentsService.getInstance().getDomesticPaymentById(paymentId);
		return ResponseEntity.ok().body(response);
	}
	
	/**
	 * Get funds-confirmation by consent id.
	 *
	 * @param id
	 *            the consent id
	 * @return the OBWriteDomesticConsentResponse2 with funds-confirmation by consent id
	 * @throws ResourceNotFoundException
	 */
	@GetMapping(path = "/domestic-payment-consents/{id}/funds-confirmation", produces = "application/json")
	@JsonDeserialize(using = DateTimeDeserializer.class)
	public ResponseEntity<OBWriteFundsConfirmationResponse1> getFundsConfirmationByConsentId(@PathVariable(value = "id") String consentId) throws ResourceNotFoundException {
		OBWriteFundsConfirmationResponse1 response = DomesticPaymentsService.getInstance().getFundsConfirmationByConsentId(consentId);
		return ResponseEntity.ok().body(response);
	}
}
