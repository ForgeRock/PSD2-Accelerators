package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBExternalRequestStatus1Code;
import uk.org.openbanking.datamodel.account.OBReadConsent1;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1;
import uk.org.openbanking.datamodel.account.OBReadConsentResponse1Data;
import uk.org.openbanking.datamodel.account.OBRisk2;

public class AccountAccessConsentsService {

	private static final Logger log = LoggerFactory.getLogger(AccountAccessConsentsService.class);

	private List<OBReadConsentResponse1> responseList;
	private static int consentId = 88379;
	private static AccountAccessConsentsService stdregd = null;

	private AccountAccessConsentsService() {
		responseList = new ArrayList<>();
	}

	public static AccountAccessConsentsService getInstance() {
		if (stdregd == null) {
			stdregd = new AccountAccessConsentsService();
			return stdregd;
		} else {
			return stdregd;
		}
	}

	public OBReadConsentResponse1 createConsent(OBReadConsent1 obReadConsent1) {
		if (null == obReadConsent1) {
			throw new ResourceNotFoundException("Create consent un-successful.");
		}
		String strConsentId = "surn-alphabank-intent-"+consentId;
		OBReadConsentResponse1Data data = new OBReadConsentResponse1Data();
		data.consentId(strConsentId);
		data.setStatus(OBExternalRequestStatus1Code.AWAITINGAUTHORISATION);
		data.setCreationDateTime(new DateTime("2017-05-02T00:00:00+00:00"));
		data.setStatusUpdateDateTime(new DateTime("2017-05-02T00:00:00+00:00"));

		BeanUtils.copyProperties(obReadConsent1.getData(), data);
		Links links = new Links();
		links.setSelf(String.format("https://api.alphabank.com/open-banking/v3.1/aisp/account-access-consents/%s", strConsentId));
		Meta defaultMeta = MetaService.getInstance().getDefault();
		OBRisk2 risk = obReadConsent1.getRisk();
		
		OBReadConsentResponse1 response = new OBReadConsentResponse1();
		response.setData(data);
		response.setLinks(links);
		response.setMeta(defaultMeta);
		response.setRisk(risk);
		responseList.add(response);
		consentId++;
		return response;
	}

	public OBReadConsentResponse1 getConsentById(String consentId)
			throws ResourceNotFoundException {

		for (OBReadConsentResponse1 response : responseList) {
			if (StringUtils.equals(response.getData().getConsentId(), consentId)) {
				return response;
			}
		}

		throw new ResourceNotFoundException(String.format("Consent with id %s not found!", consentId));
	}

	public String deleteConsentById(String consentId) throws ResourceNotFoundException {
		for (int i = 0; i < responseList.size(); i++) {
			OBReadConsentResponse1 response = responseList.get(i);
			if (StringUtils.equals(response.getData().getConsentId(), consentId)) {
				responseList.remove(i);
				return "Delete successful";
			}
		}
		throw new ResourceNotFoundException("Delete un-successful. Consent not found on id :: " + consentId);
	}

}
