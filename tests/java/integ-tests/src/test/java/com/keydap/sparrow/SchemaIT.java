/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import com.google.gson.JsonObject;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class SchemaIT extends TestBase {
    /**
     * 3.1 List schemas
     */
    @Test
    public void testListSchemas() {
        Response<List<JsonObject>> resp = unAuthClient.getSchemas();
        List<JsonObject> lst = resp.getResource();
        assertNotNull(lst);
        assertTrue(lst.size() >= 2); // User and Group schemas are a MUST
        
        for(JsonObject jo : lst) {
            fetchSchema(jo);
        }
    }
    
    /**
     * 3.2 Retrieve a single schema
     * 
     * @param jo
     */
    private void fetchSchema(JsonObject jo) {
        String id = jo.get("id").getAsString();
        Response<JsonObject> resp = unAuthClient.getSchema(id);
        JsonObject rt = resp.getResource();
        assertNotNull(rt);
        assertEquals(id, rt.get("id").getAsString());
    }
}
