/*
 * Copyright (c) 2018 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.rbac;

import static org.junit.Assert.assertEquals;

import org.apache.http.HttpStatus;
import org.junit.Test;

import com.keydap.sparrow.Response;
import com.keydap.sparrow.scim.User;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class AddAuthorizationTest extends RbacTestBase {
    
    @Test
    public void testAdd() {
        User u = buildUser();
        Response<User> resp = readOnlyClient.addResource(u);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());

        resp = partialReadClient.addResource(u);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = partialWriteClient.addResource(u);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = writeOnlyClient.addResource(u);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
    }
}
