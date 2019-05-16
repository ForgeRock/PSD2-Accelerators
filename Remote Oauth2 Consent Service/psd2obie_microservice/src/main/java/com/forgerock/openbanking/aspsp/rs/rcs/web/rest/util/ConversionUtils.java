/***************************************************************************
 *  Copyright 2019 ForgeRock
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ***************************************************************************/
package com.forgerock.openbanking.aspsp.rs.rcs.web.rest.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ConversionUtils {
	
	 private static final Logger log = LoggerFactory.getLogger(ConversionUtils.class);
	 private ConversionUtils() {
	    }
	 public static Date setDateParsing(String date, String fromat) throws ParseException {	
	    // This format date is actually present
	    SimpleDateFormat formatter = new SimpleDateFormat(fromat);
	    log.info("formatter : {}",fromat);
	    log.info("date : {}",date);
	    return formatter.parse(date);
	}
	 public static boolean isTimeExpired(String initialDateString, int interval, String dateFormat, int field) throws ParseException {
		 
		 Calendar initalDate = Calendar.getInstance();
		 initalDate.setTime(setDateParsing(initialDateString,dateFormat));
		 //Calendar.MINUTE
		 initalDate.add(field, interval);
		 
		 Calendar current = Calendar.getInstance();
		 log.info("intialDate : {}",initalDate.getTime());
		 log.info("time : {}",interval);
		 log.info("field : {}",field);	
		 log.info("currentDate : {}",current.getTime());	
		 return initalDate.before(current);
		 
	 } 	
	 public static String setDateFormating(Date date, String fromat) throws ParseException {	
		    // This format date is actually present
		    SimpleDateFormat formatter = new SimpleDateFormat(fromat);
		    log.info("formatter : {}",fromat);
		    log.info("date : {}",date);
		    return formatter.format(date);
		}
}
