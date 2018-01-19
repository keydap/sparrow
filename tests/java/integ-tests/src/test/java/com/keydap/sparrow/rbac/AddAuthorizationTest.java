/*
 * Copyright (c) 2018 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.rbac;

import static org.junit.Assert.*;

import java.util.List;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.http.HttpStatus;
import org.junit.Test;

import com.keydap.sparrow.PatchGenerator;
import com.keydap.sparrow.PatchRequest;
import com.keydap.sparrow.Response;
import com.keydap.sparrow.SearchRequest;
import com.keydap.sparrow.SearchResponse;
import com.keydap.sparrow.scim.User;
import com.keydap.sparrow.scim.User.Email;
import com.keydap.sparrow.scim.User.EnterpriseUser;

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
        
        resp = denyAllClient.addResource(u);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = writeOnlyClient.addResource(u);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        
        u = buildUser();
        resp = mixedUnionClient.addResource(u);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
    }
    
    @Test
    public void testDelete() {
        User u = buildUser();
        Response<User> createResp = writeOnlyClient.addResource(u);
        assertEquals(HttpStatus.SC_CREATED, createResp.getHttpCode());
        u = createResp.getResource();
        
        Response<Boolean> resp = readOnlyClient.deleteResource(u.getId(), User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());

        resp = partialReadClient.deleteResource(u.getId(), User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = partialWriteClient.deleteResource(u.getId(), User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = denyAllClient.deleteResource(u.getId(), User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = mixedUnionClient.deleteResource(u.getId(), User.class);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
    }
    
    @Test
    public void testReplace() {
        User u = buildUser();
        Response<User> resp = writeOnlyClient.addResource(u);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        u = resp.getResource();
        String id = u.getId();
        String version = resp.getETag();
        
        User replacement = buildUser();
        replacement.setUserName(u.getUserName()); // just set the username to same and change everything
        
        resp = readOnlyClient.replaceResource(id, replacement, version);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());

        resp = partialReadClient.replaceResource(id, replacement, version);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = partialWriteClient.replaceResource(id, replacement, version);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = denyAllClient.replaceResource(id, replacement, version);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = mixedUnionClient.replaceResource(id, replacement, version);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        u = resp.getResource();
        assertEquals(replacement.getDisplayName(), u.getDisplayName());
    }
    
    @Test
    public void testPatch() {
        User original = buildUser();
        Response<User> resp = writeOnlyClient.addResource(original);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        original = resp.getResource();
        String id = original.getId();
        String version = resp.getETag();
        
        User modified = buildUser();
        modified.setUserName(original.getUserName()); // just set the username to same and change everything

        PatchGenerator pg = new PatchGenerator();
        PatchRequest pr = pg.create(id, modified, original, version);
        pr.setAttributes("*");
        resp = readOnlyClient.patchResource(pr);
        
        resp = partialReadClient.patchResource(pr);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = partialWriteClient.patchResource(pr);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = denyAllClient.patchResource(pr);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = mixedUnionClient.patchResource(pr);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        User patched = resp.getResource();
        assertEquals(modified.getDisplayName(), patched.getDisplayName());
        version = resp.getETag();
        
        // now modify emails with partialWriteClient, should pass
        patched.setEmails(original.getEmails());
        modified.setPassword(null); // set the password to null cause patched resource has no password
        pr = pg.create(id, patched, modified, version);
        pr.setAttributes("*");
        resp = partialWriteClient.patchResource(pr);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        User patched2 = resp.getResource();
        version = resp.getETag();
        compareEmails(original.getEmails(), patched2.getEmails());
        
        // now modify emails AND Name.familyname attribute with partialWriteClient, should fail
        patched2.setEmails(patched.getEmails());
        patched2.getName().setFamilyName("A");
        pr = pg.create(id, patched2, patched, version);
        resp = partialWriteClient.patchResource(pr);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
    }
    
    @Test
    public void testGet() {
        User original = buildUser();
        Response<User> resp = writeOnlyClient.addResource(original);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        original = resp.getResource();
        String id = original.getId();
        
        resp = readOnlyClient.getResource(id, User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        
        resp = partialReadClient.getResource(id, User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        User fetched = resp.getResource();
        assertNull(fetched.getDisplayName()); // the role PartialReadAny allows read access to only username and emails
        compareEmails(original.getEmails(), fetched.getEmails());
        assertEquals(original.getUserName(), fetched.getUserName());

        resp = enterpriseReadOnlyClient.getResource(id, User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        fetched = resp.getResource();
        assertNull(fetched.getDisplayName()); // the role EnterpriseReadOnly allows read access to username and enterprise user attributes
        assertNull(fetched.getEmails());
        assertNotNull(fetched.getEnterpriseUser());
        assertTrue(EqualsBuilder.reflectionEquals(original.getEnterpriseUser(), fetched.getEnterpriseUser(), false));
        assertEquals(original.getUserName(), fetched.getUserName());

        // id and schemas are mandatory attributes
        assertNotNull(fetched.getId());
        assertNotNull(fetched.getSchemas());
        
        resp = partialWriteClient.getResource(id, User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = denyAllClient.getResource(id, User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = writeOnlyClient.getResource(id, User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = mixedUnionClient.getResource(id, User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        
        // test with excluded attributes
        resp = partialReadClient.getResource(id, User.class, false, "emails");
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        fetched = resp.getResource();
        assertNull(fetched.getDisplayName()); // the role PartialReadAny allows read access to only username and emails
        assertNull(fetched.getEmails());
        assertEquals(original.getUserName(), fetched.getUserName());
    }

    @Test
    public void testSearch() {
        User u1 = buildUser();
        User u2 = buildUser();
        writeOnlyClient.addResource(u1);
        writeOnlyClient.addResource(u2);
        
        SearchResponse<User> resp = readOnlyClient.searchResource(User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        
        resp = partialReadClient.searchResource(User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        assertTrue(resp.getResources().size() >= 2);
        for(User fetched : resp.getResources()) {
            assertNull(fetched.getDisplayName()); // the role PartialReadAny allows read access to only username and emails
            assertNotNull(fetched.getEmails());
            assertNotNull(fetched.getUserName());
            // id and schemas are mandatory attributes
            assertNotNull(fetched.getId());
            assertNotNull(fetched.getSchemas());
        }
        
        
        resp = partialWriteClient.searchResource(User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = denyAllClient.searchResource(User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = writeOnlyClient.searchResource(User.class);
        assertEquals(HttpStatus.SC_FORBIDDEN, resp.getHttpCode());
        
        resp = mixedUnionClient.searchResource(User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        
        // test with excluded attributes
        SearchRequest sr = new SearchRequest();
        sr.setExcludedAttributes("emails");
        resp = partialReadClient.searchResource(sr, User.class);
        assertTrue(resp.getResources().size() >= 2);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        for(User fetched : resp.getResources()) {
            assertNull(fetched.getDisplayName()); // the role PartialReadAny allows read access to only username and emails
            assertNull(fetched.getEmails());
            assertNotNull(fetched.getUserName());
        }

        sr = new SearchRequest();
        sr.setAttributes(EnterpriseUser.SCHEMA+":*");
        sr.setFilter("costCenter pr");
        resp = enterpriseReadOnlyClient.searchResource(sr, User.class);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        for(User fetched : resp.getResources()) {
            assertNull(fetched.getDisplayName()); // the role EnterpriseReadOnly allows read access to username and enterprise user attributes
            assertNull(fetched.getEmails());
            assertNotNull(fetched.getEnterpriseUser());
        }
    }
    
    private void compareEmails(List<Email> lst1, List<Email> lst2) {
        assertEquals(lst1.size(), lst2.size());
        int matchCount = 0;
        for(Email e1 : lst1) {
            for(Email e2 : lst1) {
                boolean eq = EqualsBuilder.reflectionEquals(e1, e2, true);
                if(eq) {
                    matchCount++;
                    break;
                }
            }
        }
        
        assertEquals(lst1.size(), matchCount);
    }
}
