package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBBeneficiary2;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBReadBeneficiary2;
import uk.org.openbanking.datamodel.account.OBReadBeneficiary2Data;

public class BeneficiariesService {
	
	private static final Logger log = LoggerFactory.getLogger(BeneficiariesService.class);
	
	private OBReadBeneficiary2 response;
	private OBReadBeneficiary2Data data;
	private List<OBBeneficiary2> beneficiaryList;
	private static BeneficiariesService stdregd = null;

	private BeneficiariesService() {

		data = new OBReadBeneficiary2Data();
		beneficiaryList = getDefaultBeneficiaryList();
		data.setBeneficiary(beneficiaryList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/beneficiaries/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadBeneficiary2();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static BeneficiariesService getInstance() {
		if (stdregd == null) {
			stdregd = new BeneficiariesService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadBeneficiary2 getBeneficiaries() {
		data.setBeneficiary(beneficiaryList);
		response.setData(data);
		return response;
	}
	
	public OBReadBeneficiary2 getBeneficiaryByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/beneficiaries/", accountId);
		List<OBBeneficiary2> newBeneficiaryList = new ArrayList<OBBeneficiary2>();
		for (OBBeneficiary2 beneficiary : beneficiaryList) {
			if (StringUtils.equals(beneficiary.getAccountId(), accountId)) {
				newBeneficiaryList.add(beneficiary);
				break;
			}
		}
		if (newBeneficiaryList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Beneficiary with account id %s not found!", accountId));
		}
		data.setBeneficiary(newBeneficiaryList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBBeneficiary2> getDefaultBeneficiaryList() {
		
		List<OBBeneficiary2> beneficiaryList = new ArrayList<>();
		
		/* First beneficiary */
		OBBeneficiary2 beneficiary1 = new OBBeneficiary2();
		beneficiary1.setAccountId("22289");
		beneficiary1.setBeneficiaryId("Ben1");
		beneficiary1.setReference("Towbar Club");
		
		OBCashAccount3 cashAccount1 = new OBCashAccount3();
		cashAccount1.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount1.setIdentification("80200112345678");
		cashAccount1.setName("Mrs Juniper");
		beneficiary1.setCreditorAccount(cashAccount1);
		beneficiaryList.add(beneficiary1);
		
		/* Second beneficiary */
		OBBeneficiary2 beneficiary2 = new OBBeneficiary2();
		beneficiary2.setAccountId("31820");
		beneficiary2.setBeneficiaryId("Ben37");
		beneficiary2.setReference("Golf Club");
		
		OBCashAccount3 cashAccount2 = new OBCashAccount3();
		cashAccount2.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount2.setIdentification("87562298675421");
		cashAccount2.setName("Mr Large");
		beneficiary2.setCreditorAccount(cashAccount2);
		beneficiaryList.add(beneficiary2);

		return beneficiaryList;
	}

}
