package com.forgerock.service.fundsConfirmation;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.fund.OBFundsConfirmationConsent1;
import uk.org.openbanking.datamodel.fund.OBFundsConfirmationConsentDataResponse1;
import uk.org.openbanking.datamodel.fund.OBFundsConfirmationConsentResponse1;

public class FundsConfirmationConsentService {

	private static final Logger log = LoggerFactory.getLogger(FundsConfirmationConsentService.class);

	private List<OBFundsConfirmationConsentResponse1> responseList;
	private static int fundsConfirmationId = 10000;
	private static FundsConfirmationConsentService stdregd = null;

	private FundsConfirmationConsentService() {
		responseList = new ArrayList<>();
	}

	public static FundsConfirmationConsentService getInstance() {
		if (stdregd == null) {
			stdregd = new FundsConfirmationConsentService();
			return stdregd;
		} else {
			return stdregd;
		}
	}

	public OBFundsConfirmationConsentResponse1 createFundsConfirmationConsent(
			OBFundsConfirmationConsent1 fundsConfirmationConsent1) {
		if (null == fundsConfirmationConsent1) {
			throw new ResourceNotFoundException("Create consent un-successful.");
		}
		OBFundsConfirmationConsentDataResponse1 data = new OBFundsConfirmationConsentDataResponse1();
		data.consentId("" + fundsConfirmationId);
		// data.setCreationDateTime(new DateTime("2017-06-05T15:15:13+00:00"));
		// data.setStatusUpdateDateTime(new DateTime("2017-06-05T15:15:13+00:00"));

		BeanUtils.copyProperties(fundsConfirmationConsent1.getData(), data);
		Links links = new Links();
		links.setSelf(String.format("https://api.alphabank.com/open-banking/v3.1/pisp/funds-confirmation-consents/%s",
				fundsConfirmationId));

		OBFundsConfirmationConsentResponse1 response = new OBFundsConfirmationConsentResponse1();
		response.setData(data);
		response.setLinks(links);
		responseList.add(response);
		fundsConfirmationId++;
		return response;
	}

	public OBFundsConfirmationConsentResponse1 getFundsConfirmationConsentByConsentId(String consentId)
			throws ResourceNotFoundException {

		for (OBFundsConfirmationConsentResponse1 response : responseList) {
			if (StringUtils.equals(response.getData().getConsentId(), consentId)) {
				return response;
			}
		}

		throw new ResourceNotFoundException(String.format("Consent with id %s not found!", consentId));
	}

	public String deleteFundsConfirmationConsentByConsentId(String consentId) throws ResourceNotFoundException {
		for (int i = 0; i < responseList.size(); i++) {
			OBFundsConfirmationConsentResponse1 response = responseList.get(i);
			if (StringUtils.equals(response.getData().getConsentId(), consentId)) {
				responseList.remove(i);
				return "Delete successful";
			}
		}
		throw new ResourceNotFoundException("Delete un-successful. Consent not found on id :: " + consentId);
	}

}
