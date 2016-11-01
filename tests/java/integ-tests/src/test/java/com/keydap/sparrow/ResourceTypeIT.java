/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import java.util.List;

import org.junit.Test;
import static org.junit.Assert.*;

import com.google.gson.JsonObject;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class ResourceTypeIT extends TestBase {
    /**
     * 2.1 List resource types
     */
    @Test
    public void testListResourceTypes() {
        Response<List<JsonObject>> resp = unAuthClient.getResTypes();
        List<JsonObject> lst = resp.getResource();
        assertNotNull(lst);
        assertTrue(lst.size() >= 2); // User and Group resources are a MUST
        
        for(JsonObject jo : lst) {
            fetchRT(jo);
        }
    }
    
    /**
     * 2.2 Retrieve a single resource type
     * 
     * @param jo
     */
    private void fetchRT(JsonObject jo) {
        String name = jo.get("name").getAsString();
        Response<JsonObject> resp = unAuthClient.getResType(name);
        JsonObject rt = resp.getResource();
        assertNotNull(rt);
        assertEquals(name, rt.get("name").getAsString());
    }
}
