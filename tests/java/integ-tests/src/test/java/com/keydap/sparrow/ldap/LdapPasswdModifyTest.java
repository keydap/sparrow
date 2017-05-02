/*
 * Copyright (c) 2017 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.charset.Charset;

import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keydap.sparrow.SparrowClient;
import com.keydap.sparrow.TestBase;
import com.keydap.sparrow.auth.SparrowAuthenticator;
import com.keydap.sparrow.scim.User;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class LdapPasswdModifyTest extends TestBase {
    private LdapNetworkConnection ldapCon;
    
    private LdapNetworkConnection adminLdapCon;

    private Charset utf8 = Charset.forName("utf-8");
    
    private static final String DN_TEMPLATE = "uid=%s,dc=example,dc=com";
   
    @Before
    public void connect() throws Exception {
        ldapCon = new LdapNetworkConnection("localhost", 7092);
        ldapCon.setTimeOut(Long.MAX_VALUE);
        ldapCon.getConfig().setTrustManagers(new NoVerificationTrustManager());
        ldapCon.connect();
        ldapCon.startTls();
        
        adminLdapCon = new LdapNetworkConnection("localhost", 7092);
        adminLdapCon.setTimeOut(Long.MAX_VALUE);
        adminLdapCon.getConfig().setTrustManagers(new NoVerificationTrustManager());
        adminLdapCon.connect();
        adminLdapCon.startTls();
        adminLdapCon.bind(String.format(DN_TEMPLATE, "admin"), "secret");
    }

    @After
    public void close() throws Exception {
    	ldapCon.close();
    	adminLdapCon.close();
    }
    
    @Test
    public void testModifyPasswordAsAdmin() throws Exception {
        User u = buildUser();
        String oldPassword = u.getPassword();
        client.addResource(u);
        
        String newPassword = "secret002";
        
        PasswordModifyRequest pmr = new PasswordModifyRequestImpl();
        pmr.setUserIdentity((u.getUserName()).getBytes(utf8));
        pmr.setOldPassword(oldPassword.getBytes(utf8));
        pmr.setNewPassword(newPassword.getBytes(utf8));
        
        ExtendedResponse eResp = adminLdapCon.extended(pmr);
        assertEquals(ResultCodeEnum.SUCCESS, eResp.getLdapResult().getResultCode());
        
        try {
            SparrowClient uClient = createClient(u.getUserName(), oldPassword);
            uClient.authenticate();
            fail("shouldn't authenticate with old password after changing password");
        }
        catch(Exception e) {
            // pass
        }
        
        SparrowClient uClient = createClient(u.getUserName(), newPassword);
        uClient.authenticate();
    }
    
    @Test
    public void testModifyPasswordAsSelf() throws Exception {
        User u = buildUser();
        String oldPassword = u.getPassword();
        client.addResource(u);
        
        ldapCon.bind(String.format(DN_TEMPLATE, u.getUserName()), oldPassword);
        
        String newPassword = "secret002";
        
        PasswordModifyRequest pmr = new PasswordModifyRequestImpl();
        pmr.setUserIdentity((u.getUserName()).getBytes(utf8));
        pmr.setOldPassword(oldPassword.getBytes(utf8));
        pmr.setNewPassword(newPassword.getBytes(utf8));
        
        ExtendedResponse eResp = ldapCon.extended(pmr);
        assertEquals(ResultCodeEnum.SUCCESS, eResp.getLdapResult().getResultCode());
        
        try {
            SparrowClient uClient = createClient(u.getUserName(), oldPassword);
            uClient.authenticate();
            fail("shouldn't authenticate with old password after changing password");
        }
        catch(Exception e) {
            // pass
        }
        
        SparrowClient uClient = createClient(u.getUserName(), newPassword);
        uClient.authenticate();
    }

    @Test
    public void testModifyPasswordAsNonAdmin() throws Exception {
        User u = buildUser();
        String oldPassword = u.getPassword();
        client.addResource(u);
        
        ldapCon.bind(String.format(DN_TEMPLATE, u.getUserName()), oldPassword);
        
        String newPassword = "secret002";
        
        PasswordModifyRequest pmr = new PasswordModifyRequestImpl();
        pmr.setUserIdentity("admin".getBytes(utf8));
        pmr.setOldPassword("secret".getBytes(utf8));
        pmr.setNewPassword(newPassword.getBytes(utf8));
        
        ExtendedResponse eResp = ldapCon.extended(pmr);
        assertEquals(ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS, eResp.getLdapResult().getResultCode());
        
        try {
            SparrowClient uClient = createClient(u.getUserName(), oldPassword);
            uClient.authenticate();
            // pass
        }
        catch(Exception e) {
        	fail("shouldn't authenticate with old password after changing password");
        }
    }
    
    @Test
    public void testModifyPasswordAsSelfWithoutExistingSess() throws Exception {
        User u = buildUser();
        String oldPassword = u.getPassword();
        client.addResource(u);
        
        String newPassword = "secret002";
        
        PasswordModifyRequest pmr = new PasswordModifyRequestImpl();
        // when there is no session a complete DN is required
        pmr.setUserIdentity(String.format(DN_TEMPLATE, u.getUserName()).getBytes(utf8));
        pmr.setOldPassword(oldPassword.getBytes(utf8));
        pmr.setNewPassword(newPassword.getBytes(utf8));
        
        ExtendedResponse eResp = ldapCon.extended(pmr);
        assertEquals(ResultCodeEnum.SUCCESS, eResp.getLdapResult().getResultCode());
        
        try {
            SparrowClient uClient = createClient(u.getUserName(), oldPassword);
            uClient.authenticate();
            fail("shouldn't authenticate with old password after changing password");
        }
        catch(Exception e) {
            // pass
        }
        
        SparrowClient uClient = createClient(u.getUserName(), newPassword);
        uClient.authenticate();
    }

    private SparrowClient createClient(String username, String password) {
        SparrowAuthenticator authenticator = new SparrowAuthenticator(username, "example.com", password);
        return new SparrowClient(baseApiUrl, authenticator);
    }
    
}
