package com.forgerock.service.payment;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;

import com.forgerock.exceptions.BadRequestException;
import com.forgerock.exceptions.ResourceNotFoundException;
import com.forgerock.service.accountAndTransaction.LinksService;
import com.forgerock.service.accountAndTransaction.MetaService;
import com.forgerock.service.accountAndTransaction.RiskService;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.payment.OBExternalConsentStatus1Code;
import uk.org.openbanking.datamodel.payment.OBFundsAvailableResult1;
import uk.org.openbanking.datamodel.payment.OBRisk1;
import uk.org.openbanking.datamodel.payment.OBTransactionIndividualStatus1Code;
import uk.org.openbanking.datamodel.payment.OBWriteDataDomesticConsentResponse2;
import uk.org.openbanking.datamodel.payment.OBWriteDataDomesticResponse2;
import uk.org.openbanking.datamodel.payment.OBWriteDataFundsConfirmationResponse1;
import uk.org.openbanking.datamodel.payment.OBWriteDomestic2;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsent2;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsentResponse2;
import uk.org.openbanking.datamodel.payment.OBWriteDomesticResponse2;
import uk.org.openbanking.datamodel.payment.OBWriteFundsConfirmationResponse1;

public class DomesticPaymentsService {
	
	private static final Logger log = LoggerFactory.getLogger(DomesticPaymentsService.class);
	

	private OBWriteDomesticConsentResponse2 responseConsent;
	private List<OBWriteDomesticConsentResponse2> responseConsentList;
	private OBWriteDataDomesticConsentResponse2 dataConsent;
	private static int paymentConsentId = 58923;

	private OBWriteDomesticResponse2 responsePayment;
	private List<OBWriteDomesticResponse2> responsePaymentList;
	private OBWriteDataDomesticResponse2 dataPayment;
	private static Integer paymentId = 3;
	
	private Links links;
	private Meta meta;
	private OBRisk1 risk;
	final static private String HOST_URL="https://openig.psd2acceldemo.fridam.aeet-forgerock.com:443/openbanking/v3.1";

	private static DomesticPaymentsService stdregd = null;

	private DomesticPaymentsService() {
		links = LinksService.getInstance().getDefault();
		meta = MetaService.getInstance().getDefault();
		risk = RiskService.getInstance().getDefault();
		
		initiateDomesticPaymentConsent();
		initiateDomesticPayment();

	}

	private void initiateDomesticPaymentConsent(){
		responseConsentList = new ArrayList<>();
		dataConsent = new OBWriteDataDomesticConsentResponse2();

		responseConsent = new OBWriteDomesticConsentResponse2();
		responseConsent.setData(dataConsent);
		responseConsent.setLinks(links);
		responseConsent.setMeta(meta);
		responseConsent.setRisk(risk);
	}
	
	private void initiateDomesticPayment(){
		responsePaymentList = new ArrayList<>();
		dataPayment = new OBWriteDataDomesticResponse2();

		responsePayment = new OBWriteDomesticResponse2();
		responsePayment.setData(dataPayment);
		responsePayment.setLinks(links);
		responsePayment.setMeta(meta);
	}
	
	public static DomesticPaymentsService getInstance() {
		if (stdregd == null) {
			stdregd = new DomesticPaymentsService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBWriteDomesticConsentResponse2 createDomesticPaymentConsent(OBWriteDomesticConsent2 domesticPaymentConsent) {
		if (null==domesticPaymentConsent) {
			throw new ResourceNotFoundException("Create consent un-successful.");
		}
		OBWriteDataDomesticConsentResponse2 dataConsent = new OBWriteDataDomesticConsentResponse2();
		dataConsent.consentId(""+paymentConsentId);
		dataConsent.setStatus(OBExternalConsentStatus1Code.AWAITINGAUTHORISATION);
		dataConsent.setCreationDateTime(new DateTime());
		dataConsent.setStatusUpdateDateTime(new DateTime());

		BeanUtils.copyProperties(domesticPaymentConsent.getData(), dataConsent);
		Links links = new Links();
		links.setSelf(String.format("%s/domestic-payment-consents/%s",HOST_URL, paymentConsentId));
		OBRisk1 risk = domesticPaymentConsent.getRisk();
		
		OBWriteDomesticConsentResponse2 responseConsent = new OBWriteDomesticConsentResponse2();
		responseConsent.setData(dataConsent);
		responseConsent.setLinks(links);
		responseConsent.setRisk(risk);
		responseConsentList.add(responseConsent);
		paymentConsentId++;
		return responseConsent;
	}
	
	public OBWriteDomesticConsentResponse2 getDomesticPaymentConsentById(String consentId) throws ResourceNotFoundException {

		for (OBWriteDomesticConsentResponse2 response : responseConsentList) {
			if (StringUtils.equals(response.getData().getConsentId(), consentId)) {
				return response;
			}
		}

		throw new ResourceNotFoundException(String.format("Consent with id %s not found!", consentId));
	}
	
	public OBWriteFundsConfirmationResponse1 getFundsConfirmationByConsentId(String consentId)
			throws ResourceNotFoundException, BadRequestException {

//		OBWriteDomesticConsentResponse2 consentResponse = getDomesticPaymentConsentById(consentId);

//		if (null == consentResponse) {
//			throw new ResourceNotFoundException(String.format("Consent with id %s not found!", consentId));
//		}

//		if (!OBExternalConsentStatus1Code.AUTHORISED.equals(consentResponse.getData().getStatus())) {
//			throw new BadRequestException("UK.OBIE.Resource.InvalidConsentStatus");
//		}

		OBFundsAvailableResult1 fundsAvailable = new OBFundsAvailableResult1();
		fundsAvailable.setFundsAvailableDateTime(new DateTime());
		fundsAvailable.setFundsAvailable(true);

		OBWriteDataFundsConfirmationResponse1 confirmationData = new OBWriteDataFundsConfirmationResponse1();
		confirmationData.setFundsAvailableResult(fundsAvailable);
		Links links = new Links();
		links.setSelf(String.format(
				"%s/domestic-payment-consents/%s/funds-confirmation",
				HOST_URL, consentId));

		OBWriteFundsConfirmationResponse1 confirmationResponse = new OBWriteFundsConfirmationResponse1();
		confirmationResponse.setData(confirmationData);
		confirmationResponse.setLinks(links);
		confirmationResponse.setMeta(new Meta());

		return confirmationResponse;
	}
	
	public OBWriteDomesticResponse2 createDomesticPayment(OBWriteDomestic2 domesticPayment) {
		if (null==domesticPayment) {
			throw new ResourceNotFoundException("Create payment un-successful.");
		}
		String consentId = domesticPayment.getData().getConsentId();
		StringBuilder sb = new StringBuilder();
		sb.append(consentId).append("-");
		switch (String.valueOf(paymentId).length()) {
		case 1:
			sb.append("00").append(paymentId);
			break;
		case 2:
			sb.append("0").append(paymentId);
			break;
		default:
			sb.append(paymentId);
			break;
		}
		OBWriteDataDomesticResponse2 dataPayment = new OBWriteDataDomesticResponse2();
		dataPayment.setDomesticPaymentId(sb.toString());
		dataPayment.consentId(consentId);
		dataPayment.setStatus(OBTransactionIndividualStatus1Code.ACCEPTEDSETTLEMENTINPROCESS);
		dataPayment.setCreationDateTime(new DateTime());
		dataPayment.setStatusUpdateDateTime(new DateTime());

		BeanUtils.copyProperties(domesticPayment.getData(), dataPayment);
		Links links = new Links();
		links.setSelf(String.format("%s/domestic-payments/%s", HOST_URL,sb.toString()));
		OBWriteDomesticResponse2 responsePayment = new OBWriteDomesticResponse2();
		responsePayment.setData(dataPayment);
		responsePayment.setLinks(links);
		responsePayment.setMeta(new Meta());
		responsePaymentList.add(responsePayment);
		paymentId++;
		return responsePayment;
	}
	
	public OBWriteDomesticResponse2 getDomesticPaymentById(String paymentId) {

		for (OBWriteDomesticResponse2 response : responsePaymentList) {
			if (StringUtils.equals(response.getData().getDomesticPaymentId(), paymentId)) {
				return response;
			}
		}

		throw new ResourceNotFoundException(String.format("Payment with id %s not found!", paymentId));
	}

}
