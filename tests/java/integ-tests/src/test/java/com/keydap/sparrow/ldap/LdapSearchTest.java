/*
 * Copyright (c) 2017 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
@Ignore
public class LdapSearchTest {
    private static LdapNetworkConnection con;
    
    @BeforeClass
    public static void connect() throws Exception {
        //System.setProperty("javax.net.debug", "ssl");
        con = new LdapNetworkConnection("localhost", 7092);
        con.getConfig().setTrustManagers(new NoVerificationTrustManager());
        con.connect();
        con.startTls();
        con.bind("uid=admin,dc=example,dc=com", "secret");
    }
    
    @Test
    public void testSearchSubtree() throws Exception {
        // subtree and onelevel are treated as same
        EntryCursor cursor = con.search("dc=example,dc=com", "(uid=*)", SearchScope.SUBTREE, "*");
        int count = 0;
        while(cursor.next()) {
            assertNotNull(cursor.get());
            count++;
        }
        
        assertNotNull(cursor.getSearchResultDone());
        assertTrue(count > 0);
        cursor.close();
    }
    
    @Test
    public void testSearchObject() throws Exception {
        String userDn = "uid=admin,ou=Users,dc=example,dc=com";
        String groupDn = "cn=Administrator,ou=Groups,dc=example,dc=com";

        Entry user = searchOne(userDn, "(uid=*)");
        assertEquals(groupDn.toLowerCase(), user.get("member").getString().toLowerCase());
        
        Entry group = searchOne(groupDn, "(cn=*)");
        assertEquals(userDn.toLowerCase(), group.get("uniqueMember").getString().toLowerCase());
    }
    
    private Entry searchOne(String dn, String filter) throws Exception {
        EntryCursor cursor = con.search(dn, filter, SearchScope.OBJECT, "*");
        int count = 0;
        Entry e = null;
        while(cursor.next()) {
            e = cursor.get();
            count++;
        }
        
        assertNotNull(cursor.getSearchResultDone());
        cursor.close();
        
        assertEquals(1, count);
        
        return e;
    }
}
