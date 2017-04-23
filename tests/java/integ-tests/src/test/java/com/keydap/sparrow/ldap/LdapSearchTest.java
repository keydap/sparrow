/*
 * Copyright (c) 2017 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.ldap;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
@Ignore
public class LdapSearchTest {
    private static LdapNetworkConnection con;
    
    @BeforeClass
    public static void connect() throws Exception {
        con = new LdapNetworkConnection("localhost", 7092);
        con.connect();
    }
    
    @Test
    public void testBind() throws Exception {
        con.bind("uid=admin,dc=example,dc=com", "secret");
    }
    
    @Test
    public void testSearchSubtree() throws Exception {
        // subtree and onelevel are treated as same
        EntryCursor cursor = con.search("dc=example,dc=com", "(uid=*)", SearchScope.SUBTREE, "*");
        while(cursor.next()) {
            assertNotNull(cursor.get());
        }
        
        assertNotNull(cursor.getSearchResultDone());
        
        cursor.close();
    }
    
    @Test
    public void testSearchObject() throws Exception {
        EntryCursor cursor = con.search("uid=admin,dc=example,dc=com", "(uid=*)", SearchScope.OBJECT, "*");
        int count = 0;
        while(cursor.next()) {
            System.out.println(cursor.get());
            count++;
        }
        
        assertNotNull(cursor.getSearchResultDone());
        cursor.close();
        
        assertEquals(1, count);
    }
}
