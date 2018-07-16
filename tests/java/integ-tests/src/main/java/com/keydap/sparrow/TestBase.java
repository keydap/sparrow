/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import java.lang.reflect.Field;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.TimeZone;

import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;
import org.apache.http.HttpStatus;
import org.junit.BeforeClass;

import com.keydap.sparrow.auth.SparrowAuthenticator;
import com.keydap.sparrow.scim.Device;
import com.keydap.sparrow.scim.Group;
import com.keydap.sparrow.scim.User;
import com.keydap.sparrow.scim.User.Email;
import com.keydap.sparrow.scim.User.EnterpriseUser;
import com.keydap.sparrow.scim.User.Name;

import static org.apache.commons.lang.RandomStringUtils.randomAlphabetic;
import static org.junit.Assert.*;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public abstract class TestBase {
    
    private static String BASE = "http://localhost:7090";
//    private static String BASE = "https://id.keydap.com";
    
    protected static String baseApiUrl = BASE + "/v2";
    
    protected static String baseOauthUrl = BASE + "/oauth2";
    
    protected static String baseIdpUrl = BASE + "/saml/idp";

    protected static SparrowClient client;
    
    /** the anonymous client */
    static SparrowClient unAuthClient;
    
    static DateFormat utcDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");//RFC3339

    static SparrowAuthenticator authenticator;

    @BeforeClass
    public static void createClient() throws Exception {
        authenticator = new SparrowAuthenticator("admin", "example.COM", "secret");

        client = new SparrowClient(baseApiUrl, baseOauthUrl, authenticator);
        client.register(User.class, Group.class, Device.class, RegisteredApp.class);
        utcDf.setTimeZone(TimeZone.getTimeZone("UTC"));

        client.authenticate();
        assertNotNull(authenticator.getToken());
        System.out.println(authenticator.getToken());
        
        unAuthClient = new SparrowClient(baseApiUrl);
        unAuthClient.register(User.class, Group.class, Device.class, RegisteredApp.class);
    }
    
    public static <T> void deleteAll(Class<T> resClass) {
        SearchResponse<T> resp = client.searchResource("id pr", resClass, "id", "username");
        List<T> existing = resp.getResources();
        if(existing != null) {
            try {
                Field id = resClass.getDeclaredField("id");
                id.setAccessible(true);
                
                for(T u : existing) {
                    Response<Boolean> delResp = client.deleteResource(id.get(u).toString(), resClass);
                    if(delResp.getHttpCode() != HttpStatus.SC_NO_CONTENT) {
                        //System.out.println(delResp.getHttpBody());
                    }
                }
            }
            catch(Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static LdapNetworkConnection createLdapCon(String userDn, String password) throws Exception {
        LdapNetworkConnection con = new LdapNetworkConnection("localhost", 7092);
        con.getConfig().setTrustManagers(new NoVerificationTrustManager());
        con.connect();
        con.startTls();
        con.bind(userDn, password);
        return con;
    }
    
    protected Email searchMails(User user, String mailType) {
        List<Email> emails = user.getEmails();
        for(Email m : emails) {
            if(m.getType().equalsIgnoreCase(mailType)) {
                return m;
            }
        }
        
        return null;
    }
    
    protected static SparrowClient createClient(String username, String password) throws Exception {
        SparrowAuthenticator authenticator = new SparrowAuthenticator(username, "example.COM", password);

        SparrowClient client = new SparrowClient(baseApiUrl, baseOauthUrl, authenticator);
        client.register(User.class, Group.class, Device.class, RegisteredApp.class);
        client.authenticate();
        
        return client;
    }
    
    protected static User buildUser() {
        String username = randomAlphabetic(5);
        return buildUser(username);
    }
    
    protected static User buildUser(String username) {
        User user = new User();
        user.setUserName(username);
        user.setDisplayName("display-" + username);
        
        Name name = new Name();
        name.setFamilyName(username);
        name.setGivenName(username);
        name.setHonorificPrefix("Mr.");
        name.setFormatted(name.getHonorificPrefix() + " " + name.getGivenName() + " " + name.getFamilyName());
        user.setName(name);
        
        List<Email> emails = new ArrayList<Email>();
        
        Email homeMail = new Email();
        homeMail.setDisplay("Home Email");
        homeMail.setType("home");
        String s = randomAlphabetic(5);
        homeMail.setValue(s + "@home.com" );
        emails.add(homeMail);
        
        Email workMail = new Email();
        workMail.setDisplay("Work Email");
        workMail.setType("work");
        s = randomAlphabetic(5);
        workMail.setValue(s + "@work.com" );
        emails.add(workMail);
        
        user.setEmails(emails);
        user.setActive(true);
        
        user.setPassword(randomAlphabetic(11));
        
        EnterpriseUser eu = new EnterpriseUser();
        eu.setCostCenter(username);
        eu.setDepartment("Sales");
        eu.setDivision("EU");
        eu.setEmployeeNumber(username);
        eu.setOrganization(username);
        user.setEnterpriseUser(eu);
        
        return user;
    }
}
