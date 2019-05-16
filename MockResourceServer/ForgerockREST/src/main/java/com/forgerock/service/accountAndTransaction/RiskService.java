package com.forgerock.service.accountAndTransaction;

import java.util.Arrays;

import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.payment.OBExternalPaymentContext1Code;
import uk.org.openbanking.datamodel.payment.OBRisk1;
import uk.org.openbanking.datamodel.payment.OBRisk1DeliveryAddress;

public class RiskService {
	
	private OBRisk1 risk;
	private static RiskService stdregd = null;

	private RiskService(){
		risk = new OBRisk1();
    }

	public static RiskService getInstance() {
		if (stdregd == null) {
			stdregd = new RiskService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBRisk1 getDefault(){
		OBRisk1 risk = new OBRisk1();
//		risk.setPaymentContextCode(OBExternalPaymentContext1Code.ECOMMERCEGOODS);
//		risk.setMerchantCategoryCode("5967");
//		risk.setMerchantCustomerIdentification("053598653254");
//		
//		OBRisk1DeliveryAddress address = new OBRisk1DeliveryAddress();
//		address.setAddressLine(Arrays.asList("Flat 7", "Acacia Lodge"));
//		address.setStreetName("Acacia Avenue");
//		address.setBuildingNumber("27");
//		address.setPostCode("GU31 2ZZ");
//		address.setTownName("Sparsholt");
//		address.setCountrySubDivision(Arrays.asList("Wessex"));
//		address.setCountry("UK");
//		risk.setDeliveryAddress(address);

		return risk;
	}

}
