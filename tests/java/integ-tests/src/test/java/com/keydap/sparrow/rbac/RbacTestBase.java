/*
 * Copyright (c) 2018 Keydap Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * See LICENSE file for details.
 */
package com.keydap.sparrow.rbac;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.keydap.sparrow.Response;
import com.keydap.sparrow.SearchResponse;
import com.keydap.sparrow.SparrowClient;
import com.keydap.sparrow.TestBase;
import com.keydap.sparrow.scim.Group;
import com.keydap.sparrow.scim.Group.Member;
import com.keydap.sparrow.scim.Group.Permission;
import com.keydap.sparrow.scim.User;

/**
 *
 * @author Kiran Ayyagari (kayyagari@keydap.com)
 */
public class RbacTestBase extends TestBase {
    protected static User uReadOnly;
    protected static User uWriteOnly;
    protected static User uPartialRead;
    protected static User uPartialWrite;
    protected static User uMixedUnion;
    protected static User uDenyAll;
    protected static User uEnterpriseReadOnly;
    
    protected static SparrowClient readOnlyClient;
    protected static SparrowClient writeOnlyClient;
    protected static SparrowClient partialReadClient;
    protected static SparrowClient partialWriteClient;
    protected static SparrowClient mixedUnionClient;
    protected static SparrowClient denyAllClient;
    protected static SparrowClient enterpriseReadOnlyClient;

    @BeforeClass
    public static void setupGroups() throws Exception {
        deleteAll(User.class);
        deleteAll(Group.class);
        
        uReadOnly = buildUser("ureadonly");
        String password = uReadOnly.getPassword();
        Response<User> resp = client.addResource(uReadOnly);
        uReadOnly = resp.getResource();
        uReadOnly.setPassword(password);
        
        uWriteOnly = buildUser("uwriteonly");
        password = uWriteOnly.getPassword();
        resp = client.addResource(uWriteOnly);
        uWriteOnly = resp.getResource();
        uWriteOnly.setPassword(password);
        
        uEnterpriseReadOnly = buildUser("uenterprisereadonly");
        password = uEnterpriseReadOnly.getPassword();
        resp = client.addResource(uEnterpriseReadOnly);
        uEnterpriseReadOnly = resp.getResource();
        uEnterpriseReadOnly.setPassword(password);

        uPartialRead = buildUser("upartialread");
        password = uPartialRead.getPassword();
        resp = client.addResource(uPartialRead);
        uPartialRead = resp.getResource();
        uPartialRead.setPassword(password);

        uPartialWrite = buildUser("upartialwrite");
        password = uPartialWrite.getPassword();
        resp = client.addResource(uPartialWrite);
        uPartialWrite = resp.getResource();
        uPartialWrite.setPassword(password);
        
        uMixedUnion = buildUser("umixedunion");
        password = uMixedUnion.getPassword();
        resp = client.addResource(uMixedUnion);
        uMixedUnion = resp.getResource();
        uMixedUnion.setPassword(password);

        uDenyAll = buildUser("udenyall");
        password = uDenyAll.getPassword();
        resp = client.addResource(uDenyAll);
        uDenyAll = resp.getResource();
        uDenyAll.setPassword(password);

        Group gReadOnly = new Group();
        gReadOnly.setDisplayName("ReadOnly");
        Permission readP = new Permission();
        readP.setResName("*");
        readP.setOpsArr(OperationPermission.withAllowAttributes("read", "*", "ANY").asJsonArray());
        gReadOnly.setPermissions(Collections.singletonList(readP));
        Member readOnlyMember1 = new Member();
        readOnlyMember1.setValue(uReadOnly.getId());
        Member readOnlyMember2 = new Member();
        readOnlyMember2.setValue(uMixedUnion.getId());
        List<Member> lst = new ArrayList<>();
        lst.add(readOnlyMember1);
        lst.add(readOnlyMember2);
        gReadOnly.setMembers(lst);
        client.addResource(gReadOnly);

        Group gPartialRead = new Group();
        gPartialRead.setDisplayName("PartialReadAny");
        Permission partialReadP = new Permission();
        partialReadP.setResName("User");
        partialReadP.setOpsArr(OperationPermission.withAllowAttributes("read", "username, emails", "ANY").asJsonArray());
        gPartialRead.setPermissions(Collections.singletonList(partialReadP));
        Member partialReadOnlyMember = new Member();
        partialReadOnlyMember.setValue(uPartialRead.getId());
        gPartialRead.setMembers(Collections.singletonList(partialReadOnlyMember));
        client.addResource(gPartialRead);

        Group gEnterpriseOnlyRead = new Group();
        gEnterpriseOnlyRead.setDisplayName("EnterpriseOnlyReadAny");
        Permission enterpriseOnlyReadP = new Permission();
        enterpriseOnlyReadP.setResName("User");
        enterpriseOnlyReadP.setOpsArr(OperationPermission.withAllowAttributes("read", "username, urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:*", "ANY").asJsonArray());
        gEnterpriseOnlyRead.setPermissions(Collections.singletonList(enterpriseOnlyReadP));
        Member enterpriseReadOnlyMember = new Member();
        enterpriseReadOnlyMember.setValue(uEnterpriseReadOnly.getId());
        gEnterpriseOnlyRead.setMembers(Collections.singletonList(enterpriseReadOnlyMember));
        client.addResource(gEnterpriseOnlyRead);

        Group gWriteOnly = new Group();
        gWriteOnly.setDisplayName("WriteOnly");
        Permission writeP = new Permission();
        writeP.setResName("User");
        writeP.setOpsArr(OperationPermission.withAllowAttributes("write", "*", "ANY").asJsonArray());
        gWriteOnly.setPermissions(Collections.singletonList(writeP));
        Member writeOnlyMember1 = new Member();
        writeOnlyMember1.setValue(uWriteOnly.getId());
        Member writeOnlyMember2 = new Member();
        writeOnlyMember2.setValue(uMixedUnion.getId());
        lst = new ArrayList<>();
        lst.add(writeOnlyMember1);
        lst.add(writeOnlyMember2);
        gWriteOnly.setMembers(lst);
        client.addResource(gWriteOnly);

        Group gPartialWrite = new Group();
        gPartialWrite.setDisplayName("PartialWrite");
        Permission partialWriteP = new Permission();
        partialWriteP.setResName("User");
        partialWriteP.setOpsArr(OperationPermission.withAllowAttributes("write", "displayname, emails", "ANY").asJsonArray());
        gPartialWrite.setPermissions(Collections.singletonList(partialWriteP));
        Member partialWriteOnlyMember = new Member();
        partialWriteOnlyMember.setValue(uPartialWrite.getId());
        gPartialWrite.setMembers(Collections.singletonList(partialWriteOnlyMember));
        client.addResource(gPartialWrite);

        Group gReadAndWrite = new Group();
        gReadAndWrite.setDisplayName("ReadAndWrite");
        Permission readWriteP = new Permission();
        readWriteP.setResName("User");
        StringBuilder opsArr = new StringBuilder("[");
        opsArr.append(OperationPermission.withAllowAttributes("read", "*", "ANY").toJson()).append(",");
        opsArr.append(OperationPermission.withAllowAttributes("write", "*", "ANY").toJson()).append("]");
        readWriteP.setOpsArr(opsArr.toString());
        
        // the below permission MUST get overwritten by the above User specific permission
        Permission wildcardOverwritableP = new Permission();
        wildcardOverwritableP.setResName("*");
        wildcardOverwritableP.setOpsArr(OperationPermission.withAllowAttributes("read", "displayname", "ANY").asJsonArray());

        List<Permission> lstPerms = new ArrayList<>();
        lstPerms.add(readWriteP);
        lstPerms.add(wildcardOverwritableP);
        gReadAndWrite.setPermissions(lstPerms);
        client.addResource(gReadAndWrite);

        Group gDenyReadAndWrite = new Group();
        gDenyReadAndWrite.setDisplayName("DenyReadAndWrite");
        Permission denyReadWriteP = new Permission();
        denyReadWriteP.setResName("User");
        denyReadWriteP.setOpsArr(OperationPermission.withAllowAttributes("read", "*", "NONE").asJsonArray());
        gDenyReadAndWrite.setPermissions(Collections.singletonList(denyReadWriteP));
        client.addResource(gDenyReadAndWrite);

        readOnlyClient = createClient(uReadOnly.getUserName(), uReadOnly.getPassword());
        writeOnlyClient = createClient(uWriteOnly.getUserName(), uWriteOnly.getPassword());
        partialReadClient = createClient(uPartialRead.getUserName(), uPartialRead.getPassword());
        partialWriteClient = createClient(uPartialWrite.getUserName(), uPartialWrite.getPassword());
        mixedUnionClient = createClient(uMixedUnion.getUserName(), uMixedUnion.getPassword());
        denyAllClient = createClient(uDenyAll.getUserName(), uDenyAll.getPassword());
        enterpriseReadOnlyClient = createClient(uEnterpriseReadOnly.getUserName(), uEnterpriseReadOnly.getPassword());
    }
    
    //@AfterClass
    public static void fetchAllResources() {
        SearchResponse<User> sr = client.searchResource(User.class);
        client.normalizeKeys(sr);
        print(sr);

        System.out.println("groups");
        SearchResponse<Group> groups = client.searchResource(Group.class);
        client.normalizeKeys(groups);
        print(groups);
    }
    
    private static void print(SearchResponse sr) {
        JsonParser parser = new JsonParser();
        JsonArray arr = parser.parse(sr.getHttpBody()).getAsJsonObject().get("resources").getAsJsonArray();
        Iterator<JsonElement> itr = arr.iterator();
        while(itr.hasNext()) {
            System.out.println(itr.next());
        }

    }
}
