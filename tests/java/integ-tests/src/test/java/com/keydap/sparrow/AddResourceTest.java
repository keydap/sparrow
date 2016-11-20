/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import static com.keydap.sparrow.ScimErrorType.UNIQUENESS;
import static com.keydap.sparrow.Status.BadRequest;
import static com.keydap.sparrow.Status.Conflict;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.keydap.sparrow.scim.Device;
import com.keydap.sparrow.scim.User;
import com.keydap.sparrow.scim.User.Email;
import com.keydap.sparrow.scim.User.Name;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class AddResourceTest extends TestBase {

    private static Device thermostat;
    
    @BeforeClass
    public static void clean() throws Exception {
        deleteAll(User.class);
        deleteAll(Device.class);
        //deleteAll(Group.class);
        
        thermostat = new Device();
        thermostat.setManufacturer("GMBH");
        thermostat.setPrice(900.07);
        thermostat.setRating(2);
        thermostat.setSerialNumber("00000");
        thermostat.setInstalledDate(utcDf.parse("1947-08-14T18:30:00Z"));
    }
    
    @Test
    public void testAddResource() {
        User u = new User();
        u.setUserName("bjensen");
        Name name = new Name();
        name.setFamilyName("Jensen");
        name.setFormatted("Ben Jensen");
        name.setGivenName("Ben");
        name.setHonorificPrefix("Mr.");
        u.setName(name);
        
        Email e = new Email();
        e.setValue("bjensen@example.com");
        e.setPrimary(true);
        e.setType("home");
        
        u.setEmails(Collections.singletonList(e));
        
        u.setPassword("secret001");
        
        Response<User> resp = client.addResource(u);
        User created = resp.getResource();
        assertNotNull(created);
        assertNotNull(created.getSchemas());
        assertEquals(1, created.getSchemas().length);
        assertEquals(resp.getHttpCode(), HttpStatus.SC_CREATED);
        assertNull(resp.getError());
        
        assertTrue(resp.getLocation().endsWith(created.getId()));
        
        // compare users
        assertEquals(u.getUserName(), created.getUserName());
        assertEquals(u.getName().getFamilyName(), created.getName().getFamilyName());
        assertEquals(u.getName().getFormatted(), created.getName().getFormatted());
        assertEquals(u.getName().getGivenName(), created.getName().getGivenName());
        assertEquals(u.getName().getHonorificPrefix(), created.getName().getHonorificPrefix());
        
        assertEquals(u.getEmails().get(0).getValue(), created.getEmails().get(0).getValue());
        assertEquals(u.getEmails().get(0).isPrimary(), created.getEmails().get(0).isPrimary());
        assertEquals(u.getEmails().get(0).getType(), created.getEmails().get(0).getType());
        
        // create the same user again, we should receive 409, conflict error
        resp = client.addResource(u);
        assertNull(resp.getResource());
        assertEquals(resp.getHttpCode(), HttpStatus.SC_CONFLICT);
        Error error = resp.getError();
        assertEquals(Conflict.value(), error.getStatus());
        assertEquals(UNIQUENESS.value(), error.getScimType());
        
        System.out.println(created.getId());
    }
    
    @Test
    public void  testAddInvalidResource() {
        // create user without required userName field 
        User u = new User();
        Name name = new Name();
        name.setFamilyName("Jensen");
        name.setFormatted("Ben Jensen");
        name.setGivenName("Ben");
        name.setHonorificPrefix("Mr.");
        u.setName(name);
        
        Email e = new Email();
        e.setValue("bjensen@example.com");
        e.setPrimary(true);
        e.setType("home");
        
        u.setEmails(Collections.singletonList(e));
        
        Response<User> resp = client.addResource(u);
        assertNull(resp.getResource());
        Error err = resp.getError();
        assertEquals(BadRequest.value(), err.getStatus());
        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getHttpCode());
    }
    
    @Test
    public void testAddGroup() {
        
    }

    @Test
    public void testDeviceAddition() throws Exception {
        Response<Device> resp = client.addResource(thermostat);
        
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        Device d = resp.getResource();
        assertEquals(thermostat.getManufacturer(), d.getManufacturer());
        assertEquals(thermostat.getInstalledDate(), d.getInstalledDate());
        assertTrue(thermostat.getPrice() == d.getPrice());
        assertTrue(thermostat.getRating() == d.getRating());
        assertEquals(thermostat.getSerialNumber(), d.getSerialNumber());
    }

    @Test
    public void testInvalidTime() throws Exception {
        JsonObject json = client.serialize(thermostat);
        json.remove("installedDate");
        json.addProperty("installedDate", "1947-08-14T18:30:00");
        
        HttpPost post = new HttpPost(baseApiUrl + "/Devices");
        post.setEntity(new StringEntity(json.toString(), SparrowClient.MIME_TYPE));
        
        Response<Device> resp = client.sendRawRequest(post, Device.class);
        
        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getHttpCode());
    }

    @Test
    public void testInvalidInteger() throws Exception {
        JsonObject json = client.serialize(thermostat);
        json.remove("rating");
        json.addProperty("rating", "2.7");
        
        HttpPost post = new HttpPost(baseApiUrl + "/Devices");
        post.setEntity(new StringEntity(json.toString(), SparrowClient.MIME_TYPE));
        
        Response<Device> resp = client.sendRawRequest(post, Device.class);
        
        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getHttpCode());
    }

    @Test
    public void testInvalidDecimal() throws Exception {
        JsonObject json = client.serialize(thermostat);
        json.remove("price");
        json.addProperty("price", "2.0");
        
        HttpPost post = new HttpPost(baseApiUrl + "/Devices");
        post.setEntity(new StringEntity(json.toString(), SparrowClient.MIME_TYPE));
        
        Response<Device> resp = client.sendRawRequest(post, Device.class);
        
        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getHttpCode());
    }
    
}
