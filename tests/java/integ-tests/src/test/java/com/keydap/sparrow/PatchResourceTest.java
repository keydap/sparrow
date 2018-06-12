/*
 * Copyright (c) 2016 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow;

import static org.junit.Assert.*;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.keydap.sparrow.scim.Device;
import com.keydap.sparrow.scim.Device.Location;
import com.keydap.sparrow.scim.Group;
import com.keydap.sparrow.scim.Group.Member;
import com.keydap.sparrow.scim.User;

/**
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class PatchResourceTest extends TestBase {
    
    Device thermostat;
    
    @Before
    public void init() throws Exception {
        deleteAll(Device.class);
        deleteAll(User.class);
        deleteAll(Group.class);
        
        thermostat = new Device();
        thermostat.setManufacturer("GMBH");
        thermostat.setPrice(900.07);
        thermostat.setRating(2);
        thermostat.setSerialNumber("00000");
        thermostat.setInstalledDate(utcDf.parse("1947-08-14T18:30:00Z"));
        thermostat = client.addResource(thermostat).getResource();
    }

    
    @Test
    public void testPatchDevice() {
        Response<Device> eTagResp = client.getResource(thermostat.getId(), Device.class);

        PatchRequest pr = new PatchRequest(thermostat.getId(), Device.class, eTagResp.getETag());
        pr.add("location", "{\"latitude\": \"1.1\", \"longitude\": \"2.2\", \"desc\": \"device location\"}");
        pr.setAttributes("location");
        
        Response<Device> resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_OK, resp.getHttpCode());
        
        Device dv = resp.getResource();
        Location loc = dv.getLocation();
        assertNotNull(loc);
        assertEquals("1.1", loc.getLatitude());
        assertEquals("2.2", loc.getLongitude());
        assertEquals("device location", loc.getDesc());
        
        // when no attributes are mentioned then the server returns 204 status
        pr.setAttributes(null);
        pr.getOperations().clear();
        pr.remove("location");
        pr.setIfMatch(resp.getETag());
        resp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_NO_CONTENT, resp.getHttpCode());
    }
    
    @Test
    public void testPatchGroup() {
        User u = buildUser();
        Response<User> uResp = client.addResource(u);
        u = uResp.getResource();
        
        Group g = new Group();
        g.setDisplayName(u.getUserName() + "-group");
        Response<Group> gResp = client.addResource(g);
        g = gResp.getResource();

        String gId = g.getId();
        List<Member> members = g.getMembers();
        assertFalse(hasMemberId(u.getId(), members));
        
        // add to group
        PatchRequest pr = new PatchRequest(gId, Group.class);
        pr.setIfMatch(g.getMeta().getVersion());
        JsonObject m = new JsonObject();
        m.addProperty("value", u.getId());
        JsonArray arr = new JsonArray();
        arr.add(m);
        pr.add("members", arr);
        pr.setAttributes("*");
        Response<Group> patchedGroupResp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_OK, patchedGroupResp.getHttpCode());
        g = patchedGroupResp.getResource();
        members = g.getMembers();
        assertEquals(1, members.size());
        assertTrue(hasMemberId(u.getId(), members));
        
        // try again adding the same member, should not get added
        pr.setIfMatch(patchedGroupResp.getETag());
        patchedGroupResp = client.patchResource(pr);
        assertEquals(HttpStatus.SC_CONFLICT, patchedGroupResp.getHttpCode());
        
        g = client.getResource(gId, Group.class).getResource();
        members = g.getMembers();
        assertTrue(hasMemberId(u.getId(), members));
        uResp = client.getResource(u.getId(), User.class);
        u = uResp.getResource();
        assertNotNull(u.getGroups());
        assertTrue(hasGroupId(gId, u.getGroups()));
    }
    
    private boolean hasMemberId(String uid, List<Member> members) {
        if(members != null) {
            for(Member m : members) {
                if(m.getValue().equals(uid)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    private boolean hasGroupId(String gid, List<com.keydap.sparrow.scim.User.Group> groups) {
        if(groups != null) {
            for(com.keydap.sparrow.scim.User.Group g : groups) {
                if(g.getValue().equals(gid)) {
                    return true;
                }
            }
        }
        return false;
    }
}
