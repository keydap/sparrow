/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import org.apache.http.HttpStatus;
import org.junit.Test;
import static org.junit.Assert.*;

import com.google.gson.JsonObject;

/**
 * 
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class ServiceProviderConfigIT extends TestBase {
    /**
     * 1.1 Retrieve service provider config w/out authz
     */
    @Test
    public void testRetrieveSPConfigWithUnAuthClient() {
        Response<JsonObject> resp = unAuthClient.getSrvProvConf();
        assertResponse(resp);
    }

    /**
     * 1.2 Retrieve service provider config w/ authz
     */
    @Test
    public void testRetrieveSPConfigWithAuth() {
        Response<JsonObject> resp = client.getSrvProvConf();
        assertResponse(resp);
    }

    private void assertResponse(Response<JsonObject> resp) {
        JsonObject jo = resp.getResource();
        assertNotNull(jo);
        assertNotNull(resp.getHttpBody());
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        String schemaId = jo.get("schemas").getAsJsonArray().get(0).getAsString();
        assertEquals("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig", schemaId);
    }
}
