package com.forgerock.service.payment;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;

import com.forgerock.exceptions.ResourceNotFoundException;
import com.forgerock.pojo.AccountAndTransactionAPI;
import com.forgerock.pojo.DiscoveryApiLinksData;
import com.forgerock.pojo.DiscoveryApiLinksResponse;
import com.forgerock.pojo.PaymentInitiationAPI;

import uk.org.openbanking.datamodel.discovery.OBDiscoveryAPILinksAccount3;
import uk.org.openbanking.datamodel.discovery.OBDiscoveryAPILinksPayment4;

public class DiscoveryApiLinksService {
	

	private static final Logger log = LoggerFactory.getLogger(DiscoveryApiLinksService.class);
	

	private DiscoveryApiLinksResponse response;
	private List<DiscoveryApiLinksResponse> responseList;
	private DiscoveryApiLinksData data;
	private static long id = 15800001041L;
	private static String idSuffix = "REAAY";

	private static DiscoveryApiLinksService stdregd = null;


	private DiscoveryApiLinksService() {
		initiateDiscoveryApiLinksData();
	}

	private void initiateDiscoveryApiLinksData(){
		responseList = new ArrayList<>();
		data = new DiscoveryApiLinksData();
		response = new DiscoveryApiLinksResponse();
		response.setData(data);
	}
	
	public static DiscoveryApiLinksService getInstance() {
		if (stdregd == null) {
			stdregd = new DiscoveryApiLinksService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public DiscoveryApiLinksResponse createDiscoveryApiLinks(DiscoveryApiLinksData discoveryApiLinksData) {
		if (null==discoveryApiLinksData) {
			throw new ResourceNotFoundException("Create Api Links Data un-successful.");
		}
		
		StringBuilder sb = new StringBuilder();
		switch (String.valueOf(id).length()) {
		case 11:
			sb.append("00").append(id);
			break;
		case 12:
			sb.append("0").append(id);
			break;
		default:
			sb.append(id);
			break;
		}
		sb.append(idSuffix);
		String financialId = sb.toString();
		
		DiscoveryApiLinksData linksData = new DiscoveryApiLinksData();
		BeanUtils.copyProperties(discoveryApiLinksData, linksData);
		linksData.setFinancialId(financialId);

		DiscoveryApiLinksResponse response = new DiscoveryApiLinksResponse();
		response.setData(linksData);
		responseList.add(response);
		id++;
		return response;
	}
	
	public DiscoveryApiLinksResponse getDiscoveryApiLinksResponseById(String financialId) {

		for (DiscoveryApiLinksResponse response : responseList) {
			if (StringUtils.equals(response.getData().getFinancialId(), financialId)) {
				return response;
			}
		}
		throw new ResourceNotFoundException(String.format("Links Data with financial Id %s not found!", financialId));
	}
	
	public DiscoveryApiLinksData getDefaultData(){


		OBDiscoveryAPILinksPayment4 apiLinksPayment4 = new OBDiscoveryAPILinksPayment4();
		apiLinksPayment4.setCreateDomesticPaymentConsent("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/domestic-payment-consents");
		apiLinksPayment4.getDomesticPaymentConsent("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/domestic-payment-consents/{ConsentId}");
		apiLinksPayment4.setGetDomesticPaymentConsentsConsentIdFundsConfirmation("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/domestic-payment-consents/{ConsentId}/funds-confirmation");
		apiLinksPayment4.createDomesticPayment("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/domestic-payments");
		apiLinksPayment4.getDomesticPayment("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/domestic-payments/{DomesticPaymentId}");
		
		List<PaymentInitiationAPI> paymentInitiationAPIList = new ArrayList<>();
		PaymentInitiationAPI paymentInitiationAPI = new PaymentInitiationAPI();
		paymentInitiationAPI.setVersion("v3.1");
		paymentInitiationAPI.setApiLinksPayment4(apiLinksPayment4);
		paymentInitiationAPIList.add(paymentInitiationAPI);
		
		

		OBDiscoveryAPILinksAccount3 apiLinksAccount = new OBDiscoveryAPILinksAccount3();
		apiLinksAccount.setCreateAccountAccessConsent("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/account-access-consents");
		apiLinksAccount.setGetAccountAccessConsent("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/account-access-consents/{ConsentId}");
		apiLinksAccount.setGetAccounts("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/accounts");
		apiLinksAccount.setGetAccount("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/accounts/{AccountId}");
		apiLinksAccount.setGetAccountTransactions("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/accounts/{AccountId}/transactions");
		apiLinksAccount.setGetAccountBalances("https://openig.psd2acceldemo.fridam.aeet-forgerock.com/openbanking/v3.1/accounts/{AccountId}/balances");
		
		List<AccountAndTransactionAPI> accountAndTransactionAPIList = new ArrayList<>();
		AccountAndTransactionAPI accountAndTransactionAPI = new AccountAndTransactionAPI();
		accountAndTransactionAPI.setVersion("v3.1");
		accountAndTransactionAPI.setApiLinksAccount3(apiLinksAccount);
		accountAndTransactionAPIList.add(accountAndTransactionAPI);
		
		DiscoveryApiLinksData apiLinksData = new DiscoveryApiLinksData();
		apiLinksData.setPaymentInitiationAPIs(paymentInitiationAPIList);
		apiLinksData.setAccountAndTransactionAPIs(accountAndTransactionAPIList);
		
		return apiLinksData;
	}

}
