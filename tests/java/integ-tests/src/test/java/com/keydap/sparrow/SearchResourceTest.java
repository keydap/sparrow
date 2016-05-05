/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.http.HttpStatus;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keydap.sparrow.scim.Device;
import com.keydap.sparrow.scim.User;
import com.keydap.sparrow.scim.User.Address;
import com.keydap.sparrow.scim.User.Email;
import com.keydap.sparrow.scim.User.EnterpriseUser;
import com.keydap.sparrow.scim.User.Name;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class SearchResourceTest extends TestBase {
    
    private static User snowden;
    private static User bhagat;
    private static User assange;
    private static User stallman;
    
    private static Device thermostat;
    private static Device watch;
    private static Device mobile;
    
    private static String tDate = "1947-08-14T18:30:00Z";
    private static String wDate = "2016-05-04T14:19:14Z";
    private static String mDate = "2015-09-19T01:30:00Z";
    
    @BeforeClass
    public static void cleanAndInject() throws Exception {
        deleteAll(User.class);
        deleteAll(Device.class);
        //deleteAll(Group.class);
        
        snowden = new User();
        snowden.setUserName("snowden");
        snowden.setActive(true);
        snowden.setDisplayName("Edward J. Snowden");
        Name sName = new Name();
        sName.setFamilyName("Edward");
        sName.setFormatted(snowden.getDisplayName());
        sName.setGivenName("Snowden");
        sName.setHonorificPrefix("Mr.");
        snowden.setName(sName);
        
        Email sEmail1 = new Email();
        sEmail1.setValue("sn@eff.org");
        sEmail1.setType("work");
        sEmail1.setPrimary(true);
        
        Email sEmail2 = new Email();
        sEmail2.setValue("sn@snowden.com");
        sEmail2.setType("home");
        sEmail2.setPrimary(false);

        List<Email> sEmails = new ArrayList<Email>();
        sEmails.add(sEmail1);
        sEmails.add(sEmail2);
        snowden.setEmails(sEmails);
        
        Address sAddress = new Address();
        sAddress.setCountry("RU");
        sAddress.setLocality("St. Petersburg");
        sAddress.setStreetAddress("1st Avenue");
        snowden.setAddresses(Collections.singletonList(sAddress));
        
        snowden.setPassword("Secret001");
        snowden.setNickName("hero");

        assange = new User();
        assange.setUserName("assange");
        assange.setActive(true);
        assange.setDisplayName("Julien Assange");
        Name aName = new Name();
        aName.setFamilyName("Julien");
        aName.setFormatted(assange.getDisplayName());
        aName.setGivenName("Assange");
        aName.setHonorificPrefix("Mr.");
        assange.setName(aName);
        
        Email aEmail = new Email();
        aEmail.setDisplay("");
        aEmail.setValue("assange@wikileaks.org");
        aEmail.setType("home");
        aEmail.setPrimary(true);
        assange.setEmails(Collections.singletonList(aEmail));
        
        Address aAddress = new Address();
        aAddress.setCountry("UK");
        aAddress.setLocality("Ecaudor Embassy");
        aAddress.setStreetAddress("1st Avenue");
        assange.setAddresses(Collections.singletonList(aAddress));
        
        assange.setPassword("Secret002");
        assange.setNickName("pioneer");
        
        bhagat = new User();
        bhagat.setUserName("bhagat");
        bhagat.setActive(true);
        bhagat.setDisplayName("Bhagat Singh");
        Name bName = new Name();
        bName.setFamilyName("Singh");
        bName.setFormatted(bhagat.getDisplayName());
        bName.setGivenName("Bhagat");
        bName.setHonorificPrefix("Mr.");
        bhagat.setName(bName);
        
        Email bEmail = new Email();
        bEmail.setDisplay("");
        bEmail.setValue("bhagat@hra.org");
        bEmail.setType("home");
        bEmail.setPrimary(true);
        bhagat.setEmails(Collections.singletonList(bEmail));
        
        Address bAddress = new Address();
        bAddress.setCountry("IN");
        bAddress.setLocality("Punjab");
        bAddress.setStreetAddress("2nd Avenue");
        bhagat.setAddresses(Collections.singletonList(bAddress));
        
        bhagat.setPassword("Secret003");
        bhagat.setNickName("martyr");
        
        stallman = new User();
        stallman.setUserName("stallman");
        stallman.setActive(true);
        stallman.setDisplayName("Richard M. Stallman");
        Name rName = new Name();
        rName.setFamilyName("Richard");
        rName.setFormatted(stallman.getDisplayName());
        rName.setGivenName("Stallman");
        rName.setHonorificPrefix("Mr.");
        stallman.setName(rName);
        
        Email rEmail = new Email();
        rEmail.setDisplay("");
        rEmail.setValue("rms@fsf.org");
        rEmail.setType("home");
        rEmail.setPrimary(true);
        stallman.setEmails(Collections.singletonList(rEmail));
        
        Address rAddress = new Address();
        rAddress.setCountry("US");
        rAddress.setLocality("New York City");
        rAddress.setStreetAddress("2nd Avenue");
        stallman.setAddresses(Collections.singletonList(rAddress));
        
        stallman.setPassword("Secret004");
        stallman.setNickName("pioneer");

        EnterpriseUser stallmanEu = new EnterpriseUser();
        stallmanEu.setCostCenter("GCC");
        stallmanEu.setDivision("GNU");
        stallmanEu.setEmployeeNumber("1");
        stallmanEu.setOrganization("FSF");
        stallman.setEnterpriseUser(stallmanEu);

        client.addResource(snowden);
        client.addResource(assange);
        client.addResource(bhagat);
        client.addResource(stallman);
        
        thermostat = new Device();
        thermostat.setManufacturer("Samsung");
        thermostat.setPrice(900.07);
        thermostat.setRating(2);
        thermostat.setSerialNumber("011");
        thermostat.setInstalledDate(utcDf.parse(tDate));
        
        watch = new Device();
        watch.setManufacturer("Fossil");
        watch.setPrice(8000);
        watch.setRating(9);
        watch.setSerialNumber("002");
        watch.setInstalledDate(utcDf.parse(wDate));
        
        mobile = new  Device();
        mobile.setManufacturer("Apple");
        mobile.setPrice(53500);
        mobile.setRating(10);
        mobile.setSerialNumber("007");
        mobile.setInstalledDate(utcDf.parse(mDate));
        
        client.addResource(thermostat);
        client.addResource(watch);
        client.addResource(mobile);
    }
    
    @Test
    public void testStringComparison() {
        SearchResponse<User> resp = client.searchResource("username eq \"snowden\"", User.class);
        checkResults(resp, snowden);
        User found = resp.getResources().get(0);
        assertNull(found.getPassword()); // password should never be returned
        
        resp = client.searchResource("emails.type eq \"work\"", User.class);
        checkResults(resp, snowden);
        
        resp = client.searchResource("username ne \"snowden\"", User.class);
        checkResults(resp, assange, bhagat, stallman);

        resp = client.searchResource("name.formatted co \"l\"", User.class);
        checkResults(resp, stallman, assange);

        resp = client.searchResource("name.formatted co \"L\"", User.class);
        checkResults(resp, stallman, assange);

        resp = client.searchResource("name.familyName sw \"J\"", User.class);
        checkResults(resp, assange);

        resp = client.searchResource("name.familyName sw \"j\"", User.class);
        checkResults(resp, assange);

        resp = client.searchResource("emails.value ew \".org\"", User.class);
        checkResults(resp, stallman, assange, snowden, bhagat);

        resp = client.searchResource("emails.value ew \".com\"", User.class);
        checkResults(resp, snowden);
        
        resp = client.searchResource("emails.value ew \".COM\"", User.class);
        checkResults(resp, snowden);
        
        resp = client.searchResource("costCenter pr", User.class);
        checkResults(resp, stallman);
    }

    @Test
    public void testArithmeticOperators() {
        SearchResponse<User> uresp = client.searchResource("username gt \"snowden\"", User.class);
        checkResults(uresp, stallman);

        uresp = client.searchResource("not username gt \"snowden\"", User.class);
        checkResults(uresp, assange, bhagat, snowden);
        
        uresp = client.searchResource("username ge \"snowden\"", User.class);
        checkResults(uresp, stallman, snowden);
        
        uresp = client.searchResource("not username ge \"snowden\"", User.class);
        checkResults(uresp, assange, bhagat);
        
        uresp = client.searchResource("username lt \"snowden\"", User.class);
        checkResults(uresp, assange, bhagat);  

        uresp = client.searchResource("username le \"snowden\"", User.class);
        checkResults(uresp, assange, snowden, bhagat);        

        SearchResponse<Device> dresp = client.searchResource("rating gt  ", Device.class);
        assertEquals(HttpStatus.SC_BAD_REQUEST, dresp.getHttpCode());
        
        dresp = client.searchResource("rating eq 9", Device.class);
        checkResults(dresp, watch);

        dresp = client.searchResource("rating gt  9", Device.class);
        checkResults(dresp, mobile);

        dresp = client.searchResource("rating ge 9", Device.class);
        checkResults(dresp, watch, mobile);

        dresp = client.searchResource("price lt 900.10", Device.class);
        checkResults(dresp, thermostat);
        
        dresp = client.searchResource("price le 8000.10", Device.class);
        checkResults(dresp, thermostat, watch);

        dresp = client.searchResource("installedDate le \"2016-05-04T14:19:14Z\"", Device.class);
        checkResults(dresp, thermostat, watch, mobile);
    }
        
    @Test
    public void testLogicalOperators() {
        SearchResponse<User> resp = client.searchResource("emails[type eq \"work\" or value co \"org\"]", User.class);
        checkResults(resp, snowden, assange, bhagat, stallman);

        resp = client.searchResource("emails[type eq \"work\" and value co \"org\"]", User.class);
        checkResults(resp, snowden);

        resp = client.searchResource("emails.type eq \"work\" and emails.value co \"com\"", User.class);
        checkResults(resp, snowden);
        
        resp = client.searchResource("unknownAttribute eq \"work\" and emails.value co \"com\"", User.class);
        checkResults(resp);
        
        resp = client.searchResource("not costCenter pr", User.class);
        checkResults(resp, snowden, assange, bhagat);
    }

    private void checkResults(SearchResponse<User> resp, User... ids) {
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        List<User> received = resp.getResources();
        
        if(ids != null && ids.length > 0) {
            int expectedCount = ids.length;
            assertEquals(expectedCount, received.size());
            for(User r : received) {
                for(User i : ids) {
                    if (i.getUserName().equals(r.getUserName())) {
                        expectedCount--;
                    }
                }
            }
            
            if(expectedCount != 0) {
                fail("All the expected users are not present in the Response");
            }
        } else {
            assertNull(received);
        }
    }

    private void checkResults(SearchResponse<Device> resp, Device... ids) {
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        List<Device> received = resp.getResources();
        
        if(ids != null && ids.length > 0) {
            int expectedCount = ids.length;
            assertEquals(expectedCount, received.size());
            for(Device r : received) {
                for(Device i : ids) {
                    if (i.getSerialNumber().equals(r.getSerialNumber())) {
                        expectedCount--;
                    }
                }
            }
            
            if(expectedCount != 0) {
                fail("All the expected devices are not present in the Response");
            }
        } else {
            assertNull(received);
        }
    }
}
