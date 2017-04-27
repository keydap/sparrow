/*
 * Copyright (c) 2017 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.ldap;

import java.nio.charset.Charset;

import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

import com.keydap.sparrow.SparrowClient;
import com.keydap.sparrow.TestBase;
import com.keydap.sparrow.auth.SparrowAuthenticator;
import com.keydap.sparrow.scim.User;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class LdapPasswdModifyTest extends TestBase {
    private static LdapNetworkConnection ldapCon;
    
    private static LdapNetworkConnection adminLdapCon;

    private Charset utf8 = Charset.forName("utf-8");
    
    
    @BeforeClass
    public static void connect() throws Exception {
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
        adminLdapCon.bind("uid=admin,dc=example,dc=com", "secret");
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
    }
    
    private SparrowClient createClient(String username, String password) {
        SparrowAuthenticator authenticator = new SparrowAuthenticator(username, "example.com", password);
        return new SparrowClient(baseApiUrl, authenticator);
    }
    
}
