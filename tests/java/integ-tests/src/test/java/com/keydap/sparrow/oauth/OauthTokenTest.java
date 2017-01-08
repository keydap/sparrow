/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.Consts;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.client.HttpClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.WebDriverWait;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Tests fetching of a OAuth token using a mix of httpclient
 * and selenium toolkits
 * 
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class OauthTokenTest {

    public static String baseOauthUrl = "http://localhost:7090/oauth2";

    private static final String CTX_PATH = "/tokentest";
    private static final int PORT = 7000;
    private static final String LOCALHOST = "localhost";
    
    private static Server server;
    
    static String redirectUri = "http://" + LOCALHOST + ":" + PORT + CTX_PATH;
    static HttpClient oHttpClient;
    
    static CloseableHttpClient httpClient;
    
    static String spResponse = null;
    
    static String code;
    
    JsonParser parser = new JsonParser();
    
    static WebDriver browser;
    
    static {
        System.setProperty("webdriver.gecko.driver", "/Users/dbugger/bin/geckodriver");
    }
    
    @BeforeClass
    public static void setup() throws Exception {
        httpClient = HttpClientBuilder.create().build();
        oHttpClient = new URLConnectionClient();
    
        browser = new FirefoxDriver();
        
        InetSocketAddress isa = new InetSocketAddress(LOCALHOST, PORT);
        server = new Server(isa);
        
        AbstractHandler handler = new AbstractHandler() {
            
            @Override
            public void handle(String target,  Request baseRequest,
                    HttpServletRequest request,  HttpServletResponse response)
                    throws IOException, ServletException {
                
                if(!target.endsWith("/tokentest")) {
                    return;
                }
                
                code = baseRequest.getParameter("code");
                
                InputStream in = request.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(in));
                String s = null;
                spResponse = "";
                while((s = br.readLine()) != null) {
                    spResponse += s + "\n";
                }
                br.close();
                response.setStatus(HttpServletResponse.SC_OK);
            }
        };
        
        server.setHandler(handler);
        
        server.start();
    }
    
    @AfterClass
    public static void stop() throws Exception {
        browser.quit();
        server.stop();
    }
    
    @Test
    public void testOauthTokenReq() throws Exception {
        String template = baseOauthUrl + "/register?uri=%s&desc=token-test-client";
        template = String.format(template, URLEncoder.encode(redirectUri, "utf-8"));
        HttpPost register = new HttpPost(template);
        HttpResponse regResp = httpClient.execute(register);
        assertEquals(HttpStatus.SC_CREATED, regResp.getStatusLine().getStatusCode());
        JsonObject regObj = parseJson(regResp);
        
        String clientId = regObj.get("id").getAsString();
        String secret = regObj.get("secret").getAsString();
        
        browser.get(baseOauthUrl + "/authorize?client_id=" + clientId);
        
        WebElement username = browser.findElement(By.name("username"));
        username.sendKeys("admin");
        
        WebElement password = browser.findElement(By.name("password"));
        password.sendKeys("secret");
        
        WebElement login = browser.findElement(By.id("login"));
        login.click();
        
        new WebDriverWait(browser, 20).until(new ExpectedCondition<Boolean>() {

            @Override
            public Boolean apply(WebDriver wd) {
                String content = wd.getPageSource();
                //System.out.println(content);
                return content.contains("authorize()");
            }
        });
        
        WebElement authorize = browser.findElement(By.id("authz"));
        authorize.click();
        
        Thread.sleep(1000);
        
        browser.quit();
        
        assertNotNull(code);
        
        String basicHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        
        HttpPost tokenReq = new HttpPost(baseOauthUrl + "/token");
        tokenReq.addHeader(HttpHeaders.AUTHORIZATION, basicHeader);
        List<NameValuePair> lst = new ArrayList<NameValuePair>();
        lst.add(new BasicNameValuePair("grant_type", "authorization_code"));
        lst.add(new BasicNameValuePair("code", code));
        tokenReq.setEntity(new UrlEncodedFormEntity(lst, Consts.UTF_8));
        
        HttpResponse tokenResp = httpClient.execute(tokenReq);
        assertEquals(HttpStatus.SC_OK, tokenResp.getStatusLine().getStatusCode());
        JsonObject token = parseJson(tokenResp);
        assertNotNull(token.get("access_token"));
        assertEquals("bearer", token.get("token_type").getAsString());
    }
    
    private JsonObject parseJson(HttpResponse resp) throws Exception {
        StatusLine sl = resp.getStatusLine();
        System.out.println(sl);
        
        String json = EntityUtils.toString(resp.getEntity());
        System.out.println(json);
        
        JsonObject obj = (JsonObject) parser.parse(json);
        assertNotNull(obj);
        
        return obj;
    }
}