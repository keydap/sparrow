/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import static org.apache.commons.lang.RandomStringUtils.randomAlphabetic;
import static org.junit.Assert.*;
import static org.junit.Assert.assertNotNull;
import static org.unitils.reflectionassert.ReflectionAssert.assertLenientEquals;
import static org.unitils.reflectionassert.ReflectionAssert.assertReflectionEquals;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.unitils.reflectionassert.ReflectionComparatorMode;
import org.unitils.util.ReflectionUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.keydap.sparrow.scim.User;
import com.keydap.sparrow.scim.User.Address;
import com.keydap.sparrow.scim.User.Email;
import com.keydap.sparrow.scim.User.Meta;
import com.keydap.sparrow.scim.User.Name;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class UserResourceIT extends TestBase {
    
    @Before
    public void cleanUsers() {
        deleteAll(User.class);
    }
    
    /**
     * <pre>
     * 4.1  Create a user - verify attributes are saved and 201 response with a full user is returned
     * 4.2 Create a user with a multi-valued complex attribute
     * <strike>4.3 Create a user with a $ref attribute</strike> (not covered cause Sparrow sets the proper $ref type while associating with a group)
     * 4.4 Create a user with an immutable attribute
     * <strike>4.5  Create a user with attributes query param (both core and extended attributes) - verify only requested attributes are returned
     * 4.6 Create a user with excludedAttributes query param (both core and extended attributes) - verify only requested attributes are returned</strike>
     * </pre>
     */
    @Test
    public void testCreateAndVerifyResponse() throws Exception {
        String username = "elecharny";
        User user = new User();
        user.setUserName(username);
        
        Name name = new Name();
        name.setFamilyName("Lécharny");
        name.setGivenName("Emmanuel");
        name.setHonorificPrefix("Mr.");
        name.setFormatted(name.getHonorificPrefix() + " " + name.getGivenName() + " " + name.getFamilyName());
        user.setName(name);
        
        List<Email> emails = new ArrayList<Email>();
        
        Email homeMail = new Email();
        homeMail.setDisplay("Home Email");
        String s = randomAlphabetic(5);
        homeMail.setValue(s + "@home.com" );
        emails.add(homeMail);
        
        Email workMail = new Email();
        workMail.setDisplay("Work Email");
        s = randomAlphabetic(5);
        workMail.setValue(s + "@work.com" );
        emails.add(workMail);
        
        user.setEmails(emails);
        
        Response<User> resp = client.addResource(user);
        User createdUser = resp.getResource();
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        assertNotNull(createdUser);
        // id meta and schemas are generated on server, so check for them
        // then set those fields in 'user' instance before comparing
        assertNotNull(createdUser.getId());
        assertNotNull(createdUser.getMeta());
        assertNotNull(createdUser.getSchemas());
        ReflectionUtils.setFieldValue(user, "id", createdUser.getId());
        ReflectionUtils.setFieldValue(user, "meta", createdUser.getMeta());
        ReflectionUtils.setFieldValue(user, "schemas", createdUser.getSchemas());
        
        assertReflectionEquals(user, createdUser, ReflectionComparatorMode.LENIENT_ORDER);
    }
    
    /**
     * 4.7  Create a user with attributes not supported by server (extension and core) - should be ignored
     * @throws Exception
     */
    @Test
    public void testCreateWithOneUnknownAttr() throws Exception {
        String username = randomAlphabetic(5);
        User user = new User();
        user.setUserName(username);
        
        Name name = new Name();
        name.setFamilyName(username);
        name.setGivenName(username);
        name.setHonorificPrefix("Mr.");
        name.setFormatted(name.getHonorificPrefix() + " " + name.getGivenName() + " " + name.getFamilyName());
        user.setName(name);
        
        JsonObject json = client.serialize(user);
        json.addProperty("xyz-attribute", "unknown");
        
        HttpPost post = new HttpPost(baseApiUrl + "/Users");
        StringEntity entity = new StringEntity(json.toString(), ScimClient.MIME_TYPE);
        post.setEntity(entity);

        Response<User> resp = client.sendRawRequest(post, User.class);
        // sparrow enforces strict schema checks 
        /*
        User createdUser = resp.getResource();
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        assertNotNull(createdUser);
        // id meta and schemas are generated on server, so check for them
        // then set those fields in 'user' instance before comparing
        assertNotNull(createdUser.getId());
        assertNotNull(createdUser.getMeta());
        assertNotNull(createdUser.getSchemas());
        ReflectionUtils.setFieldValue(user, "id", createdUser.getId());
        ReflectionUtils.setFieldValue(user, "meta", createdUser.getMeta());
        ReflectionUtils.setFieldValue(user, "schemas", createdUser.getSchemas());
        
        assertReflectionEquals(user, createdUser, ReflectionComparatorMode.LENIENT_ORDER);
        */
    }
    
    /**
     * 4.8  Create a user with missing required attributes - should fail
     * 4.9  Create a user with a non-unique value for a unique attribute - should fail 
     */
    @Test
    public void testUniqueFields() {
        String username = randomAlphabetic(5);
        User user = new User();
        user.setUserName(username);

        // check with missing required field
        user.setUserName(null);
        Response<User> resp = client.addResource(user);
        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getHttpCode());
        
        user.setUserName(username);
        resp = client.addResource(user);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        
        // create another user with the same name
        resp = client.addResource(user);
        assertEquals(HttpStatus.SC_CONFLICT, resp.getHttpCode());
    }
    
    /**
     * <pre>
     * 5.1 Update user - verify attributes are saved and 200 response with a full user is returned
     * 5.2 Update a user with a multi-valued complex attribute
     * 5.3 Update a user with a $ref attribute
     * Sparrow updates $ref attribute automatically based on the type of the referred resource, so
     * the below three cases are not applicable for User and Group resources. These tests are covered
     * using Device type. 
     * <strike>5.4 Update an immutable attribute that was previously null - value should be set</strike>
     * <strike>5.5 Update an immutable attribute that has a value, setting it to the same value - should succeed</strike>
     * <strike>5.6 Update an immutable attribute that has a value, setting it to a different value - should fail</strike>
     * 5.7 Update a readOnly attribute - should be ignored
     * 5.11 Update a user with missing required attributes - should fail
     * 5.13 Update a user with non-matching If-Match etag header - should return a 412 status code and not update the user
     * 5.14 Update a user with matching If-Match etag header - should update
     * </pre>
     */
    @Test
    public void testReplace() throws Exception {
        User user = buildUser();
        String username = user.getUserName();
        
        Response<User> userResp = client.addResource(user);
        assertEquals(HttpStatus.SC_CREATED, userResp.getHttpCode());
        user = userResp.getResource();
        
        /*
        Group group = new Group();
        group.setDisplayName("Random Group");
        Member member = new Member();
        member.setValue(user.getId());
        group.setMembers(Collections.singletonList(member));
        
        Response<Group> groupResp = client.addResource(group);
        assertEquals(HttpStatus.SC_CREATED, groupResp.getHttpCode());
        group = groupResp.getResource();
        
        groupResp = client.getResource(group.getId(), Group.class);
        group = groupResp.getResource();
        List<Member> members = group.getMembers();
        assertEquals(1, members.size());
        assertEquals(user.getId(), members.get(0).getValue());
        
        groupResp = client.getResource(group.getId(), Group.class);
        group = groupResp.getResource();
        assertNull(group.getMembers());
        */
        
        Email workMail = new Email();
        workMail.setDisplay("Work Email");
        String s = randomAlphabetic(5);
        workMail.setValue(s + "@work.com" );

        // now replace
        user.getEmails().clear();
        user.getEmails().add(workMail);
        
        Name newName = new Name();
        newName.setFamilyName("abc");
        user.setName(newName);
        //user.getRoles().clear();
        
        // change one readonly attribute, that value should be ignored
        String userId = user.getId();
        ReflectionUtils.setFieldValue(user, "id", "id-value-must-be-ignored");
        userResp = client.replaceResource(userId, user, userResp.getETag());
        assertEquals(HttpStatus.SC_OK, userResp.getHttpCode());
        User replacedUser = userResp.getResource();
        
        // replace the id and meta back in 'user' instance before comparison
        ReflectionUtils.setFieldValue(user, "id", userId);
        ReflectionUtils.setFieldValue(user, "meta", replacedUser.getMeta());
        assertLenientEquals(user, replacedUser);
        
        // 5.11    Update a user with missing required attributes - should fail
        replacedUser.setUserName(null);
        userResp = client.replaceResource(userId, replacedUser, userResp.getETag());
        assertEquals(HttpStatus.SC_BAD_REQUEST, userResp.getHttpCode());
        
        // 5.13 Update a user with non-matching If-Match etag header - should return a 412 status code and not update the user
        replacedUser.setUserName(username);
        userResp = client.replaceResource(userId, replacedUser, "in-valid-etag");
        assertEquals(HttpStatus.SC_PRECONDITION_FAILED, userResp.getHttpCode());
    }
    
    /**
     * No mention of these features in spec for PUT, not sure why they were added
     * <pre>
     * 5.8  Update a user with attributes query param (both core and extended attributes) - verify only requested attributes are returned
     * 5.9  Update a user with excludedAttributes query param (both core and extended attributes) - verify only requested attributes are returned
     * </pre>
     */
    @Ignore("5.8 and 5.9")
    @Test
    public void testUpdateWithQueryParam() {
    }
    
    /**
     * <pre>
     * 6.1  Update a simple attribute with PATCH (replace)
     * 6.2 Update a multi-valued attribute with PATCH (replace)
     * 6.3 Add a value to a multi-valued attribute with PATCH (add)
     * 6.4 Remove a value from a multi-valued attribute with PATCH (remove)
     * 6.5 Update a complex multi-valued address with a non-ambiguous filter - addresses[type eq “home” and locality eq “Redwood Shores”]
     * <strike>6.6 Update a complex multi-valued address with an ambiguous filter - addresses.type eq “home” and addresses.locality eq “Redwood Shores”</strike> - ambiguous filter is not supported in Sparrow
     * 6.7 Update a user with non-matching If-Match etag header using PATCH - should return a 412 status code and not update the user
     * </pre>
     */
    @Test
    public void testPatchSimpleAt() throws Exception {
        User user = buildUser();
        Response<User> resp = client.addResource(user);
        assertEquals(HttpStatus.SC_CREATED, resp.getHttpCode());
        user = resp.getResource();
        

        PatchRequest pr = new PatchRequest(user.getId(), User.class, resp.getETag());
        String displayName = "Mr. " + user.getUserName();
        pr.add(null, "{displayName:\"" + displayName + "\"}");
        
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
        resp = client.getResource(user.getId(), User.class);
        
        User patchedUser = resp.getResource();
        assertEquals(displayName, patchedUser.getDisplayName());
        // set displayName attribute before comparing
        user.setDisplayName(displayName);
        // compare Meta first
        Meta oldMeta = user.getMeta();
        Meta newMeta = patchedUser.getMeta();
        assertNotEquals(oldMeta.getVersion(), newMeta.getVersion());
        // can't assert the below statement cause the time difference is in milliseconds
        //assertTrue(oldMeta.getLastModified().before(newMeta.getLastModified()));
        assertEquals(oldMeta.getCreated(), newMeta.getCreated());
        
        ReflectionUtils.setFieldValue(user, "meta", null);
        ReflectionUtils.setFieldValue(patchedUser, "meta", null);
        assertReflectionEquals(user, patchedUser, ReflectionComparatorMode.LENIENT_ORDER);
        
        // update a multi-valued attribute (replace)
        pr = new PatchRequest(user.getId(), User.class);
        pr.replace("emails[type eq \"work\"]", "{value: \"abc@work.com\", display: \"new work address\"}");
        pr.setIfNoneMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
        resp = client.getResource(user.getId(), User.class);
        
        patchedUser = resp.getResource();
        
        Email workEmail = searchMails(patchedUser, "work");
        assertNotNull(workEmail);
        assertEquals("new work address", workEmail.getDisplay());
        assertEquals("abc@work.com", workEmail.getValue());
        
        // add a multivalued attribute
        Address home = new Address();
        home.setCountry("India");
        home.setLocality("Hyderabad");
        home.setType("home");

        pr = new PatchRequest(user.getId(), User.class);
        pr.replace("addresses", "[{country: \"India\", locality: \"Hyderabad\", type: \"home\"}]");
        pr.setIfNoneMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
        resp = client.getResource(user.getId(), User.class);
        
        patchedUser = resp.getResource();
        assertReflectionEquals(home, patchedUser.getAddresses().get(0), ReflectionComparatorMode.LENIENT_ORDER);
        
        //Remove a value from a multi-valued attribute with PATCH (remove)
        pr = new PatchRequest(user.getId(), User.class);
        pr.remove("emails[type eq \"work\"]");
        pr.setIfNoneMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
        resp = client.getResource(user.getId(), User.class);
        
        patchedUser = resp.getResource();
        workEmail = searchMails(patchedUser, "work");
        assertNull(workEmail);
        Email homeEmail = searchMails(patchedUser, "home");
        assertNotNull(homeEmail);
        
        //Update a complex multi-valued address with a non-ambiguous filter - addresses[type eq “home” and locality eq “Redwood Shores”]
        home = new Address();
        home.setCountry("India");
        home.setLocality("Satkol");
        home.setType("home");

        pr = new PatchRequest(user.getId(), User.class);
        pr.replace("addresses[type eq \"home\" and locality eq \"hyderabad\"]", client.serialize(home));
        pr.setIfNoneMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
        resp = client.getResource(user.getId(), User.class);
        
        patchedUser = resp.getResource();
        assertEquals("Satkol", patchedUser.getAddresses().get(0).getLocality());
        
        // (additional) update a simple attribute of a multi-valued complex attribute
        pr = new PatchRequest(user.getId(), User.class);
        pr.replace("addresses[type eq \"home\"].locality", new JsonPrimitive("Hyderabad"));
        pr.setIfNoneMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
        resp = client.getResource(user.getId(), User.class);
        patchedUser = resp.getResource();
        assertEquals("Hyderabad", patchedUser.getAddresses().get(0).getLocality());
        
        //6.6 Update a complex multi-valued address with an ambiguous filter - addresses.type eq “home” and addresses.locality eq “Redwood Shores”
        pr = new PatchRequest(user.getId(), User.class);
        pr.replace("addresses.type eq \"home\" and addresses.locality eq \"satkol\"", client.serialize(home));
        pr.setIfNoneMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getHttpCode());
        pr = new PatchRequest(user.getId(), User.class);
        
        //6.7   Update a user with non-matching If-Match etag header using PATCH - should return a 412 status code and not update the user
        pr = new PatchRequest(user.getId(), User.class);
        pr.replace("addresses[type eq \"home\"].locality", new JsonPrimitive("Hyderabad"));
        pr.setIfNoneMatch("invalid-etag");
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_PRECONDITION_FAILED, resp.getHttpCode());
    }
    
    private Email searchMails(User user, String mailType) {
        List<Email> emails = user.getEmails();
        for(Email m : emails) {
            if(m.getType().equalsIgnoreCase(mailType)) {
                return m;
            }
        }
        
        return null;
    }
    
    private User buildUser() {
        String username = randomAlphabetic(5);
        User user = new User();
        user.setUserName(username);

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
        
        return user;
    }
}
