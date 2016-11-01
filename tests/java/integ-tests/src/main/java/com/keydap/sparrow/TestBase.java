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
import java.util.List;
import java.util.TimeZone;

import org.junit.BeforeClass;

import com.keydap.sparrow.auth.SparrowAuthenticator;
import com.keydap.sparrow.scim.Device;
import com.keydap.sparrow.scim.Group;
import com.keydap.sparrow.scim.User;
import static org.junit.Assert.*;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public abstract class TestBase {
    
    static String baseApiUrl = "http://localhost:7090/v2";
    
    static ScimClient client;
    
    static DateFormat utcDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");//RFC3339

    static SparrowAuthenticator authenticator;

    @BeforeClass
    public static void createClient() throws Exception {
        authenticator = new SparrowAuthenticator("admin", "example.COM", "secret");

        client = new ScimClient(baseApiUrl, authenticator);
        client.register(User.class, Group.class, Device.class);
        utcDf.setTimeZone(TimeZone.getTimeZone("UTC"));

        client.authenticate();
        assertNotNull(authenticator.getToken());
        //System.out.println(authenticator.getToken());
    }
    
    public static <T> void deleteAll(Class<T> resClass) {
        SearchResponse<T> resp = client.searchResource("id pr", resClass, "id");
        List<T> existing = resp.getResources();
        if(existing != null) {
            try {
                Field id = resClass.getDeclaredField("id");
                id.setAccessible(true);
                
                for(T u : existing) {
                    client.deleteResource(id.get(u).toString(), resClass);
                }
            }
            catch(Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
