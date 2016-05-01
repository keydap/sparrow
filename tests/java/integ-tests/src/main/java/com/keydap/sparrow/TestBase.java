/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import org.junit.BeforeClass;

import com.keydap.sparrow.scim.Group;
import com.keydap.sparrow.scim.User;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public abstract class TestBase {
    
    static String baseApiUrl = "http://localhost:9090/v2";
    
    static ScimClient client;
    
    @BeforeClass
    public static void createClient() {
        client = new ScimClient(baseApiUrl);
        client.register(User.class, Group.class);
    }
}
