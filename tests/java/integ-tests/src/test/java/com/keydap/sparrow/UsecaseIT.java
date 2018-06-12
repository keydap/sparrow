/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import org.apache.http.HttpStatus;
import org.junit.Ignore;
import org.junit.Test;
import org.unitils.reflectionassert.ReflectionComparatorMode;

import static org.junit.Assert.*;

import com.google.gson.JsonPrimitive;
import com.keydap.sparrow.auth.Authenticator;
import com.keydap.sparrow.auth.SparrowAuthenticator;
import com.keydap.sparrow.scim.Group;
import com.keydap.sparrow.scim.Group.Member;
import com.keydap.sparrow.scim.User;

import static org.unitils.reflectionassert.ReflectionAssert.assertReflectionEquals;

import java.util.Collections;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class UsecaseIT extends TestBase {
    
    /**
     * 12.1 POST to create a new user.  GET created user and PUT it with no changes.  GET user again and ensure it is unchanged
     */
    @Ignore("There is not easy way to implement equality of multi-valued attributes without impacting performance")
    @Test
    public void testCreateReplaceGet() {
        User user = buildUser();
        Response<User> resp = client.addResource(user);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        resp = client.getResource(resp.getResource().getId(), User.class);
        user = resp.getResource();
        
        resp = client.replaceResource(user.getId(), user, resp.getETag());
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        resp = client.getResource(user.getId(), User.class);
        User unmodified = resp.getResource();
        
        assertReflectionEquals(user, unmodified, ReflectionComparatorMode.LENIENT_ORDER);
    }
    
    /**
     * 12.2 POST to create a new user.  Attempt to login as user.
     */
    @Test
    public void testCreateAndLogin() throws Exception {
        User user = buildUser();
        String username = user.getUserName();
        String password = user.getPassword();
        Response<User> resp = client.addResource(user);
        user = resp.getResource();
        
        // setting domain to null will make the server use the default domain
        Authenticator auth = new SparrowAuthenticator(username, null, password);
        SparrowClient sc = new SparrowClient(baseApiUrl, auth);
        sc.authenticate();
        
        PatchRequest pr = new PatchRequest(user.getId(), User.class);
        pr.setIfMatch(resp.getETag());
        pr.replace("active", new JsonPrimitive(false));
        resp = client.patchResource(pr);
        
        try {
            sc.authenticate();
            fail("Authentication must fail due to inactive account status");
        }
        catch(IllegalStateException e) {
            assertTrue(true);
        }
        
        pr.setIfMatch(resp.getETag());
        pr.replace("active", new JsonPrimitive(true));
        resp = client.patchResource(pr);
        sc.authenticate(); // must pass
        
        client.deleteResource(user.getId(), User.class);
        try {
            sc.authenticate();
            fail("Authentication must fail due to inactive account status");
        }
        catch(IllegalStateException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testAddDeleteGroupToUser() {
        User user = buildUser();
        Response<User> uresp = client.addResource(user);
        user = uresp.getResource();
        assertNull(user.getGroups());
        
        Group group = new Group();
        group.setDisplayName("SystemAdmin");
        Member member = new Member();
        member.setValue(user.getId());
        group.setMembers(Collections.singletonList(member));
        
        Response<Group> gresp = client.addResource(group);
        group = gresp.getResource();
        
        uresp = client.getResource(user.getId(), User.class);
        user = uresp.getResource();
        assertNotNull(user.getGroups());
        com.keydap.sparrow.scim.User.Group ugroup = user.getGroups().get(0);
        assertEquals(group.getId(), ugroup.getValue());
        assertEquals("/Groups/" + group.getId(), ugroup.get$ref());
        
        client.deleteResource(group.getId(), Group.class);
        uresp = client.getResource(user.getId(), User.class);
        user = uresp.getResource();
        assertNull(user.getGroups());
    }
}
