/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

import com.keydap.sparrow.scim.User;
import com.keydap.sparrow.scim.User.Address;
import com.keydap.sparrow.scim.User.Email;
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
    
    @BeforeClass
    public static void cleanAndInject() {
//        SearchResponse<User> resp = client.searchResource("id pr", User.class, "id");
//        List<User> existing = resp.getResources();
//        if(existing != null) {
//            for(User u : existing) {
//                client.deleteResource(u.getId(), User.class);
//            }
//        }
        
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
        client.addResource(snowden);

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
        client.addResource(assange);
        
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
        client.addResource(bhagat);
        
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
        client.addResource(stallman);
    }
    
    @Test
    public void testArithmeticOperators() {
        SearchResponse<User> resp = client.searchResource("username eq \"snowden\"", User.class);
        checkResults(resp, 1, snowden);
        User found = resp.getResources().get(0);
        assertNull(found.getPassword()); // password should never be returned
        
        resp = client.searchResource("emails.type eq \"work\"", User.class);
        checkResults(resp, 1, snowden);
        
        resp = client.searchResource("username ne \"snowden\"", User.class);
        checkResults(resp, 3, assange, bhagat, stallman);

        resp = client.searchResource("name.formatted co \"l\"", User.class);
        checkResults(resp, 2, stallman, assange);

        resp = client.searchResource("name.formatted co \"L\"", User.class);
        checkResults(resp, 2, stallman, assange);

        resp = client.searchResource("name.familyName sw \"J\"", User.class);
        checkResults(resp, 1, assange);

        resp = client.searchResource("name.familyName sw \"j\"", User.class);
        checkResults(resp, 1, assange);

        resp = client.searchResource("emails.value ew \".org\"", User.class);
        checkResults(resp, 4, stallman, assange, snowden, bhagat);

        resp = client.searchResource("emails.value ew \".com\"", User.class);
        checkResults(resp, 1, snowden);
        
        resp = client.searchResource("emails.value ew \".COM\"", User.class);
        checkResults(resp, 1, snowden);
    }

    @Test
    public void testLogicalOperators() {
        SearchResponse<User> resp = client.searchResource("emails[type eq \"work\" or value co \"org\"]", User.class);
        assertEquals(200, resp.getHttpCode());
        assertEquals(4, resp.getResources().size());

        resp = client.searchResource("emails[type eq \"work\" and value co \"org\"]", User.class);
        assertEquals(200, resp.getHttpCode());
        assertEquals(1, resp.getResources().size());

        resp = client.searchResource("emails.type eq \"work\" and emails.value co \"com\"", User.class);
        checkResults(resp, 1, snowden);
        
        resp = client.searchResource("unknownAttribute eq \"work\" and emails.value co \"com\"", User.class);
        checkResults(resp, 0);
    }

    private void checkResults(SearchResponse<User> resp, int expectedCount, User... ids) {
        assertEquals(200, resp.getHttpCode());
        List<User> received = resp.getResources();
        if (expectedCount == 0) {
            assertNull(received);
            return;
        }
        
        assertEquals(expectedCount, received.size());
        if(ids != null) {
            for(User r : received) {
                for(User i : ids) {
                    if (i.getUserName().equals(r.getUserName())) {
                        expectedCount--;
                    }
                }
            }
            
            if(expectedCount != 0) {
                fail("All the expected usernames are not present in the Response");
            }
        }
        
    }
}
