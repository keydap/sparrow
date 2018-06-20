/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

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
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.keydap.sparrow.RegisteredApp;
import com.keydap.sparrow.RegisteredApp.OauthAttribute;
import com.keydap.sparrow.RegisteredApp.SamlAttribute;
import com.keydap.sparrow.Response;
import com.keydap.sparrow.TestBase;

import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;

/**
 * Tests fetching of a OAuth token using a mix of httpclient
 * and selenium toolkits
 * 
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class OauthTokenTest extends TestBase {

    private static final String CTX_PATH = "/tokentest";
    private static final int PORT = 7000;
    private static final String LOCALHOST = "localhost";
    
    private static Server server;
    
    static String redirectUri = "http://" + LOCALHOST + ":" + PORT + CTX_PATH;
    
    static CloseableHttpClient httpClient;
    
    static String spResponse = null;
    
    static String code;
    static String idToken;
    static String samlResponse;
    static String relayState;
    
    static JsonParser parser = new JsonParser();
    
    WebDriver browser;

    String clientId;

    String clientSecret;
    String encodedRedirectUri;
    
    private static final XMLObjectBuilderFactory builderFactory;
    
    private static final UnmarshallerFactory unmarshallerFactory;
    
    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            InitializationService.initialize();
            builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static class ResponseHandler extends AbstractHandler {
        public ResponseHandler() {
            super();
        }
        
        @Override
        public void handle(String target,  Request baseRequest, HttpServletRequest request,  HttpServletResponse response) throws IOException, ServletException {
            System.out.println(baseRequest);
            code = baseRequest.getParameter("code");
            idToken = baseRequest.getParameter("id_token");
            samlResponse = baseRequest.getParameter("SAMLResponse");
            relayState = baseRequest.getParameter("RelayState");
            
            InputStream in = request.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String s = null;
            spResponse = "";
            while((s = br.readLine()) != null) {
                spResponse += s + "\n";
            }
            br.close();
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().flush();
        }
    }
    
    @Before
    public void reset() throws Exception {
        code = null;
        idToken = null;
        browser = new HtmlUnitDriver(true);
        if(clientId == null) {
            registerClient();
        }
    }
    
    @BeforeClass
    public static void setup() throws Exception {
        deleteAll(RegisteredApp.class);
        httpClient = HttpClientBuilder.create().build();

        InetSocketAddress isa = new InetSocketAddress(LOCALHOST, PORT);
        server = new Server(isa);
        
        AbstractHandler handler = new ResponseHandler();
        server.setHandler(handler);
        
        server.start();
    }
    
    @After
    public void teardown() throws Exception {
        browser.close();
    }
    
    @AfterClass
    public static void stop() throws Exception {
        server.stop();
    }
    
    private void registerClient() throws Exception {
        RegisteredApp req = new RegisteredApp();
        req.setName("test");
        req.setRedirectUri(redirectUri);
        req.add(new OauthAttribute("displayName", "displayName"));
        req.add(new OauthAttribute("email", "emails.value co \"admin\""));
        
        req.add(new SamlAttribute("displayName", "displayName"));
        req.add(new SamlAttribute("email", "emails.value"));
        req.setAcsUrl(redirectUri);
        req.setSloUrl(redirectUri);

        Response<RegisteredApp> appResp = client.registerApp(req);
        assertEquals(HttpStatus.SC_CREATED, appResp.getHttpCode());

        RegisteredApp app = appResp.getResource();
        clientId = app.getId();
        System.out.println(clientId);
        clientSecret = app.getSecret();
        System.out.println(clientSecret);
        
        encodedRedirectUri = URLEncoder.encode(app.getRedirectUri(), "utf-8");
    }
    
    @Test
    public void testOauthTokenReq() throws Exception {
        String url = baseOauthUrl + "/authorize?client_id=" + clientId + "&response_type=code&redirect_uri=" + encodedRedirectUri;
        System.out.println(url);
        browser.get(url);
        
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
        
        assertNotNull(code);
        assertNull(idToken);
        
        String basicHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
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
    
    
    @Test
    public void testOpenIdConnectTokenReq() throws Exception {
        browser.get(baseOauthUrl + "/authorize?client_id=" + clientId + "&response_type=id_token&scope=openid&redirect_uri=" + encodedRedirectUri);
        
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
        
        assertNull(code);
        assertNotNull(idToken);
        System.out.println("oidc token:");
        System.out.println(idToken);
        printToken(idToken);
        JwtConsumer consumer = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature().setSkipSignatureVerification().build();
        JwtClaims claims = consumer.processToClaims(idToken);
        assertNotNull(claims.getClaimValue("email"));
        assertNotNull(claims.getClaimValue("displayName"));
    }

    @Test
    public void testSamlRequest() throws Exception {
        AuthnRequestBuilder builder = (AuthnRequestBuilder)builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest authnReq = builder.buildObject();
        authnReq.setID("_" + UUID.randomUUID().toString());
        authnReq.setAssertionConsumerServiceURL(redirectUri);
        authnReq.setDestination(redirectUri);
        Issuer issuer = ((IssuerBuilder)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        issuer.setValue(clientId);
        authnReq.setIssuer(issuer);
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DeflaterOutputStream deflater = new DeflaterOutputStream(out);
        XMLObjectSupport.marshallToOutputStream(authnReq, deflater);
        deflater.finish();
        deflater.flush();
        
        String samlReq = Base64.getEncoder().encodeToString(out.toByteArray());
        
        samlReq = URLEncoder.encode(samlReq, "utf-8");
        String url = baseIdpUrl + "?SAMLRequest=" + samlReq + "&RelayState=" + encodedRedirectUri;
        System.out.println(url);
        browser.get(url);
        
        WebElement username = browser.findElement(By.name("username"));
        username.sendKeys("admin");
        
        WebElement password = browser.findElement(By.name("password"));
        password.sendKeys("secret");

        WebElement login = browser.findElement(By.id("login"));
        login.click();
        
        Thread.sleep(1000);

        System.out.println(samlResponse);
        System.out.println(relayState);
        
        assertNotNull(samlResponse);
        assertEquals(redirectUri, relayState);
        byte[] saml = Base64.getDecoder().decode(samlResponse);
        String str = new String(saml);
        BasicParserPool pool = new BasicParserPool();
        pool.setNamespaceAware(true);
        pool.initialize();
        org.opensaml.saml.saml2.core.Response samlResp = (org.opensaml.saml.saml2.core.Response)XMLObjectSupport.unmarshallFromInputStream(pool, new ByteArrayInputStream(saml));
        assertNotNull(samlResp);
        // TODO validate the received SAML response
    }
    private static JsonObject parseJson(HttpResponse resp) throws Exception {
        StatusLine sl = resp.getStatusLine();
        System.out.println(sl);
        
        String json = EntityUtils.toString(resp.getEntity());
        System.out.println(json);
        
        JsonObject obj = (JsonObject) parser.parse(json);
        assertNotNull(obj);
        
        return obj;
    }

    private void printToken(String token) {
        String[] parts = token.split("\\.");
        byte[] data = Base64.getDecoder().decode(parts[1]);
        System.out.println(new String(data));
    }
}
