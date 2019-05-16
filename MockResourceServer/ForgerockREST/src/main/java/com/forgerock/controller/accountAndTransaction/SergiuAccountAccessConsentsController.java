package com.forgerock.controller.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBAccount2;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBExternalAccountSubType1Code;
import uk.org.openbanking.datamodel.account.OBExternalAccountType1Code;
import uk.org.openbanking.datamodel.account.OBReadAccount2;
import uk.org.openbanking.datamodel.account.OBReadAccount2Data;

@RestController
@RequestMapping(path = "/data")
public class SergiuAccountAccessConsentsController {
	
	@GetMapping(path="/accounts", produces = "application/json")	
    public OBReadAccount2 getAccounts()
    {
		
		OBReadAccount2 obreadAccount2 = new OBReadAccount2();
		//set data
		OBReadAccount2Data obreadAccountData = new OBReadAccount2Data();
		
		
		List<OBAccount2> accounts = new ArrayList<OBAccount2>();
		List<OBCashAccount3> accounts3 = new ArrayList<OBCashAccount3>();
		List<OBCashAccount3> accounts33 = new ArrayList<OBCashAccount3>();
		
		
				
		OBAccount2 obaccount2 = new OBAccount2();
		
		obaccount2.setAccountId("22289");
		obaccount2.setCurrency("GBP");
		obaccount2.setAccountType(OBExternalAccountType1Code.PERSONAL);
		obaccount2.setAccountSubType(OBExternalAccountSubType1Code.CURRENTACCOUNT);
		obaccount2.setNickname("Bills");
		OBCashAccount3 obCashAccount3 = new OBCashAccount3();
		obCashAccount3.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		obCashAccount3.setIdentification("80200110203345");
		obCashAccount3.setName("Mr Kevin");
		obCashAccount3.setSecondaryIdentification("00021");
		accounts3.add(obCashAccount3);
		obaccount2.setAccount(accounts3);
		
		
		accounts.add(obaccount2);
		
		
OBAccount2 obaccount22 = new OBAccount2();
		
		obaccount22.setAccountId("31820");
		obaccount22.setCurrency("GBP");
		obaccount22.setAccountType(OBExternalAccountType1Code.PERSONAL);
		obaccount22.setAccountSubType(OBExternalAccountSubType1Code.CURRENTACCOUNT);
		obaccount22.setNickname("Household");
		OBCashAccount3 obCashAccount33 = new OBCashAccount3();
		obCashAccount33.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		obCashAccount33.setIdentification("80200110203348");
		obCashAccount33.setName("Mr Kevin");
		//obCashAccount33.setSecondaryIdentification("00021");
		accounts33.add(obCashAccount33);
		obaccount22.setAccount(accounts33);
		
		accounts.add(obaccount22);
		
		
		obreadAccountData.setAccount(accounts);
		obreadAccount2.setData(obreadAccountData);
		
		// set links		 
		Links links = new Links();
		links.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/");
		obreadAccount2.setLinks(links);
		
		//set meta
		Meta meta = new Meta();
		meta.setTotalPages(1);
		obreadAccount2.setMeta(meta);
		
        return obreadAccount2;
		
    }
	
	
	
	@GetMapping(path="/payments", produces = "application/json")
    public String getpayments()
    {
        return "payments";
    }

}
