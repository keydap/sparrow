/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import org.junit.Before;
import org.junit.Test;

import com.keydap.sparrow.scim.Device;
import com.keydap.sparrow.scim.Device.Location;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.apache.http.HttpStatus;

/**
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class PatchResourceTest extends TestBase {
    
    Device thermostat;
    
    @Before
    public void insertDevice() throws Exception {
        deleteAll(Device.class);
        thermostat = new Device();
        thermostat.setManufacturer("GMBH");
        thermostat.setPrice(900.07);
        thermostat.setRating(2);
        thermostat.setSerialNumber("00000");
        thermostat.setInstalledDate(utcDf.parse("1947-08-14T18:30:00Z"));
        thermostat = client.addResource(thermostat).getResource();
    }

    
    @Test
    public void testPatchDevice() {
        Response<Device> eTagResp = client.getResource(thermostat.getId(), Device.class);

        PatchRequest pr = new PatchRequest(thermostat.getId(), Device.class, eTagResp.getETag());
        pr.add("location", "{\"latitude\": \"1.1\", \"longitude\": \"2.2\", \"desc\": \"device location\"}");
        pr.setAttributes("location");
        
        Response<Device> resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        
        Device dv = resp.getResource();
        Location loc = dv.getLocation();
        assertNotNull(loc);
        assertEquals("1.1", loc.getLatitude());
        assertEquals("2.2", loc.getLongitude());
        assertEquals("device location", loc.getDesc());
        
        // when no attributes are mentioned then the server returns 204 status
        pr.setAttributes(null);
        pr.getOperations().clear();
        pr.remove("location");
        pr.setIfNoneMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
    }
}
