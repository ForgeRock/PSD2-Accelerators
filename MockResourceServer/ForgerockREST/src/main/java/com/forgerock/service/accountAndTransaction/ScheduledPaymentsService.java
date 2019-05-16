package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBCashAccount3;
import uk.org.openbanking.datamodel.account.OBExternalScheduleType1Code;
import uk.org.openbanking.datamodel.account.OBReadScheduledPayment1;
import uk.org.openbanking.datamodel.account.OBReadScheduledPayment1Data;
import uk.org.openbanking.datamodel.account.OBScheduledPayment1;
import uk.org.openbanking.datamodel.payment.OBActiveOrHistoricCurrencyAndAmount;

public class ScheduledPaymentsService {
	
	private static final Logger log = LoggerFactory.getLogger(ScheduledPaymentsService.class);
	
	private OBReadScheduledPayment1 response;
	private OBReadScheduledPayment1Data data;
	private List<OBScheduledPayment1> scheduledPaymentList;
	private static ScheduledPaymentsService stdregd = null;

	private ScheduledPaymentsService() {

		data = new OBReadScheduledPayment1Data();
		scheduledPaymentList = getDefaultScheduledPaymentList();
		data.setScheduledPayment(scheduledPaymentList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/scheduled-payments/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadScheduledPayment1();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static ScheduledPaymentsService getInstance() {
		if (stdregd == null) {
			stdregd = new ScheduledPaymentsService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadScheduledPayment1 getScheduledPayments() {
		data.setScheduledPayment(scheduledPaymentList);
		response.setData(data);
		return response;
	}
	
	public OBReadScheduledPayment1 getScheduledPaymentsByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/scheduled-payments/", accountId);
		List<OBScheduledPayment1> newScheduledPaymentsList = new ArrayList<OBScheduledPayment1>();
		for (OBScheduledPayment1 scheduledPayment : scheduledPaymentList) {
			if (StringUtils.equals(scheduledPayment.getAccountId(), accountId)) {
				newScheduledPaymentsList.add(scheduledPayment);
				break;
			}
		}
		if (newScheduledPaymentsList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Scheduled-Payments with account id %s not found!", accountId));
		}
		data.setScheduledPayment(newScheduledPaymentsList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBScheduledPayment1> getDefaultScheduledPaymentList() {
		
		List<OBScheduledPayment1> scheduledPaymentList = new ArrayList<>();
		
		/* First Scheduled-Payment */
		OBScheduledPayment1 scheduledPayment1 = new OBScheduledPayment1();
		scheduledPayment1.setAccountId("22289");
		scheduledPayment1.setScheduledPaymentId("SP03");
		scheduledPayment1.setScheduledPaymentDateTime(new DateTime("2017-05-05T00:00:00+00:00"));
		scheduledPayment1.setScheduledType(OBExternalScheduleType1Code.EXECUTION);
		
		OBActiveOrHistoricCurrencyAndAmount amount1 = new OBActiveOrHistoricCurrencyAndAmount();
		amount1.setAmount("10.00");
		amount1.setCurrency("GBP");
		scheduledPayment1.setInstructedAmount(amount1);
		
		OBCashAccount3 cashAccount1 = new OBCashAccount3();
		cashAccount1.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount1.setIdentification("23605490179017");
		cashAccount1.setName("Mr Tee");
		scheduledPayment1.setCreditorAccount(cashAccount1);
		scheduledPaymentList.add(scheduledPayment1);

		/* Second Scheduled-Payment */
		OBScheduledPayment1 scheduledPayment2 = new OBScheduledPayment1();
		scheduledPayment2.setAccountId("39570");
		scheduledPayment2.setScheduledPaymentId("SP77");
		scheduledPayment2.setScheduledPaymentDateTime(new DateTime("2017-04-05T00:00:00+00:00"));
		scheduledPayment2.setScheduledType(OBExternalScheduleType1Code.EXECUTION);
		
		OBActiveOrHistoricCurrencyAndAmount amount2 = new OBActiveOrHistoricCurrencyAndAmount();
		amount2.setAmount("12.00");
		amount2.setCurrency("GBP");
		scheduledPayment2.setInstructedAmount(amount2);
		
		OBCashAccount3 cashAccount2 = new OBCashAccount3();
		cashAccount2.setSchemeName("UK.OBIE.SortCodeAccountNumber");
		cashAccount2.setIdentification("23605490179017");
		cashAccount2.setName("Mr Tee");
		scheduledPayment2.setCreditorAccount(cashAccount2);
		scheduledPaymentList.add(scheduledPayment2);

		return scheduledPaymentList;
	}

}
