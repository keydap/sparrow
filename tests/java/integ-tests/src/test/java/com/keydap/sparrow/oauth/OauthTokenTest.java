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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.zip.DeflaterOutputStream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
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
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
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
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.keydap.sparrow.RegisteredApp;
import com.keydap.sparrow.RegisteredApp.OauthAttribute;
import com.keydap.sparrow.RegisteredApp.SamlAttribute;
import com.keydap.sparrow.Response;
import com.keydap.sparrow.TestBase;

import net.shibboleth.utilities.java.support.xml.BasicParserPool;

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
    static SSLContext ctx;
    
    static String spResponse = null;
    
    static String code;
    static String idToken;
    static String samlResponse;
    static String relayState;
    
    static JsonParser parser = new JsonParser();
    
    WebDriver browser;

    String clientId;
    String spIssuer;

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
        try {
            ctx = SSLContext.getInstance("TLS");
            X509TrustManager tm = new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authtype)
                        throws CertificateException {
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authtype)
                        throws CertificateException {
                }
            };

            ctx.init(null, new X509TrustManager[]{tm}, null);
        }
        catch(Exception e) {
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
        httpClient = HttpClientBuilder.create().setSSLContext(ctx).setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();

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
        req.setName("test" + UUID.randomUUID().toString());
        req.setRedirectUri(redirectUri);
        req.add(new OauthAttribute("displayName", "displayName"));
        req.add(new OauthAttribute("email", "emails.value co \"admin\""));
        
        // for formats see org.opensaml.saml.saml2.core.NameIDType
        req.add(new SamlAttribute("displayName", "displayName"));
        req.add(new SamlAttribute("email", "emails.value"));
        SamlAttribute nameId = new SamlAttribute("nameId", "emails.value"); // special attribute
        nameId.setFormat("test-format");
        req.add(nameId);
        req.setHomeUrl(redirectUri);
        req.setSloUrl(redirectUri);
        req.setSpIssuer("junit-test-issuer" + UUID.randomUUID().toString());
        req.setGroupIds(Collections.singletonList(adminGroupId));

        Response<RegisteredApp> appResp = client.registerApp(req);
        assertEquals(HttpStatus.SC_CREATED, appResp.getHttpCode());

        RegisteredApp app = appResp.getResource();
        clientId = app.getId();
        spIssuer = app.getSpIssuer();
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
        assertEquals("Bearer", token.get("token_type").getAsString());
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
        Issuer elIssuer = ((IssuerBuilder)builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        elIssuer.setValue(spIssuer);
        authnReq.setIssuer(elIssuer);
        
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
        //Signature signature = samlResp.getSignature();
        //validateSignature(signature);
        Signature asrtSign = samlResp.getAssertions().get(0).getSignature();
        validateSignature(asrtSign);
        
        Attribute email = getSamlAt("email", samlResp);
        String val = email.getAttributeValues().get(0).getDOM().getTextContent();
        // NameId was mapped to email for the sake of this test
        NameID nameId = samlResp.getAssertions().get(0).getSubject().getNameID();
        assertEquals(val, nameId.getValue());
        assertEquals("test-format", nameId.getFormat());
    }
    
    private void validateSignature(Signature signature) throws Exception {
        KeyInfo keyInfo = signature.getKeyInfo();
        X509Data x509Data = keyInfo.getX509Datas().get( 0 );

        CertificateFactory  cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream input = new ByteArrayInputStream(Base64.getDecoder().decode(x509Data.getX509Certificates().get( 0 ).getValue()));
        X509Certificate cert = (X509Certificate) cf.generateCertificate(input);
        
        SignatureValidator.validate(signature, new BasicX509Credential(cert));
    }
    
    private Attribute getSamlAt(String name, org.opensaml.saml.saml2.core.Response samlResp) {
        List<Attribute> attrs = samlResp.getAssertions().get(0).getAttributeStatements().get(0).getAttributes();
        for(Attribute a : attrs) {
            if(a.getName().equalsIgnoreCase(name)) {
                return a;
            }
        }
        
        return null;
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
