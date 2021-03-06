// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"github.com/pquerna/otp/totp"
	"math"
	"runtime/debug"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/rbac"
	"sparrow/schema"
	"sparrow/utils"
	"strings"
	"sync"
	"time"

	bolt "github.com/coreos/bbolt"
	logger "github.com/juju/loggo"
)

var (
	// a bucket that holds the names of the resource buckets e.g users, groups etc.
	BUC_RESOURCES = []byte("resources")

	// a bucket that holds the names of the resource buckets e.g users, groups etc.
	BUC_INDICES = []byte("indices")

	// a bucket that holds the unique ids of users that are registered for Webauthn.
	BUC_WEBAUTHN = []byte("webauthn")

	// the delimiter that separates resource and index name
	RES_INDEX_DELIM = ":"

	DUP_KEY_VAL = []byte{0}
	//DUP_INDEX_KEY_COUNT = []byte("__dup_index_key_count_e6bd4cdd-ab03-4c6b-6fbd-a64946e56942")
)

var log logger.Logger

var prvConf *conf.DomainConfig

func init() {
	log = logger.GetLogger("sparrow.silo")
}

type Silo struct {
	db         *bolt.DB                     // DB handle
	resources  map[string][]byte            // the resource buckets
	indices    map[string]map[string]*Index // the index buckets, each index name will be in the form {resource-name}:{attribute-name}
	sysIndices map[string]map[string]*Index
	schemas    map[string]*schema.Schema
	resTypes   map[string]*schema.ResourceType
	Engine     *rbac.RbacEngine
	cg         *base.CsnGenerator
	mutex      sync.Mutex
}

type Index struct {
	Bname         string // name of the bucket
	Name          string
	BnameBytes    []byte
	AllowDupKey   bool
	ValType       string // save the attribute's type name as a string
	CaseSensitive bool
	db            *bolt.DB
}

type modifyHints struct {
	modified bool
}

func (mh *modifyHints) markDirty() {
	if !mh.modified { // set only if not already marked
		mh.modified = true
	}
}

func (sl *Silo) getIndex(resName string, atName string) *Index {
	return sl.indices[resName][strings.ToLower(atName)]
}

// Gets the system index of the given name associated with the given resource
func (sl *Silo) getSysIndex(resName string, name string) *Index {
	idx := sl.sysIndices[resName][name]
	if idx == nil {
		panic(fmt.Errorf("There is no system index with the name %s in resource tyep %s", name, resName))
	}

	return idx
}

// Returns total number of tuples present in the index, excluding the count keys, if any.
func (idx *Index) getCount(tx *bolt.Tx) int64 {
	buck := tx.Bucket(idx.BnameBytes)
	/*	if idx.AllowDupKey {
			count := buck.Get(DUP_INDEX_KEY_COUNT)
			if count == nil {
				return 0
			} else {
				return utils.Btoi(count)
			}
		}
	*/
	return int64(buck.Stats().KeyN)
}

func (idx *Index) cursor(tx *bolt.Tx) *bolt.Cursor {
	idxBuck := tx.Bucket(idx.BnameBytes)

	return idxBuck.Cursor()
}

// Gets the number of values associated with the given key present in the index
func (idx *Index) keyCount(key interface{}, tx *bolt.Tx) int64 {
	log.Debugf("getting count of value %s in the index %s", key, idx.Name)
	buck := tx.Bucket(idx.BnameBytes)
	var count int64
	count = 0

	vData := idx.convert(key)

	if idx.AllowDupKey {
		dupBuck := buck.Bucket(vData)
		if dupBuck != nil {
			count = int64(dupBuck.Stats().KeyN)
			//log.Warningf("count for dup key %v is %d", key, count)
		}
	} else {
		val := buck.Get(vData)
		if val != nil {
			count = 1
		}
	}

	return count
}

// Inserts the given <attribute value, resource ID> tuple in the index
func (idx *Index) add(val interface{}, rid string, tx *bolt.Tx) error {
	log.Debugf("adding value %v of resource %s to index %s", val, rid, idx.Name)
	vData := idx.convert(val)
	buck := tx.Bucket(idx.BnameBytes)
	ridBytes := []byte(rid)

	var err error
	if idx.AllowDupKey {
		dupBuck := buck.Bucket(vData)

		firstInsert := false
		if dupBuck == nil {
			dupBuck, err = buck.CreateBucket(vData)
			if err != nil {
				return err
			}
			firstInsert = true
		}

		if !firstInsert {
			valData := dupBuck.Get(ridBytes)
			if valData != nil {
				// key already exists, return
				return nil
			}
		}

		err = dupBuck.Put(ridBytes, DUP_KEY_VAL)
		if err != nil {
			return err
		} else {
			// update count of index, this is only needed for indices supporting duplicate keys
			/*count := idx.getCount(tx)
			count++
			err = buck.Put(DUP_INDEX_KEY_COUNT, utils.Itob(count))
			if err != nil {
				return err
			}*/
		}
	} else {
		existingRid := buck.Get(vData)
		err = buck.Put(vData, ridBytes)
		if err != nil {
			return err
		}

		if existingRid != nil {
			// key already exists, or old key was replaced, no need to update count
			return nil
		}
	}

	return err
}

func (idx *Index) remove(val interface{}, rid string, tx *bolt.Tx) error {
	log.Debugf("removing value %#v of resource %s from index %s", val, rid, idx.Name)
	vData := idx.convert(val)
	buck := tx.Bucket(idx.BnameBytes)
	ridBytes := []byte(rid)

	var err error
	if idx.AllowDupKey {
		dupBuck := buck.Bucket(vData)

		if dupBuck != nil {
			existingVal := dupBuck.Get(ridBytes)
			// nothing to delete
			if existingVal == nil {
				return nil
			}

			err = dupBuck.Delete(ridBytes)
			if err != nil {
				return err
			}

			/*			cb := buck.Get(DUP_INDEX_KEY_COUNT)
						count := utils.Btoi(cb)
						count--
						err = buck.Put(DUP_INDEX_KEY_COUNT, utils.Itob(count))*/

			if dupBuck.Stats().KeyN == 1 { // the count becomes zero *after* the tx gets committed
				err = buck.DeleteBucket(vData)
				if err != nil {
					return err
				} else {
					log.Debugf("Deleting the bucket associated with %s", val)
				}
			}
		}
	} else {
		existingVal := buck.Get(vData)
		// nothing to delete
		if existingVal == nil {
			return nil
		}

		err = buck.Delete(vData)
		if err != nil {
			return err
		}
	}

	// update count of index
	/*countsBuck := tx.Bucket(BUC_COUNTS)

	count := idx.getCount(tx)
	count--
	err = countsBuck.Put(idx.BnameBytes, utils.Itob(count))
	if err != nil {
		return err
	}*/

	return err
}

// Get the resource ID associated with the given attribute value
// This method is only applicable for unique attributes
func (idx *Index) GetRid(valKey []byte, tx *bolt.Tx) string {
	buc := tx.Bucket(idx.BnameBytes)
	ridBytes := buc.Get(valKey)

	if ridBytes != nil {
		rid := string(ridBytes)
		return rid
	}

	return ""
}

// Get the resource ID associated with the given attribute value
// This method is applicable for multivalued attributes only
func (idx *Index) GetRids(valKey []byte, tx *bolt.Tx) []string {
	buck := tx.Bucket(idx.BnameBytes)

	dupBuck := buck.Bucket(valKey)

	var rids []string

	if dupBuck != nil {
		//rids = make([]string, 0)
		cur := dupBuck.Cursor()
		for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
			rids = append(rids, string(k))
		}
	}

	return rids
}

// Checks if the given key value pair exist in the index
func (idx *Index) HasKeyAndVal(key []byte, val string, tx *bolt.Tx) bool {
	buck := tx.Bucket(idx.BnameBytes)

	found := false
	if idx.AllowDupKey {
		dupBuck := buck.Bucket(key)

		if dupBuck != nil {
			valBytes := []byte(val)
			dupVal := dupBuck.Get(valBytes)
			found = (dupVal != nil)
		}
	} else {
		data := buck.Get(key)
		if data != nil {
			found = (val == string(data))
		}
	}

	return found
}

func (idx *Index) HasVal(val interface{}, tx *bolt.Tx) bool {
	if idx.AllowDupKey {
		return idx.keyCount(val, tx) > 0
	}

	key := idx.convert(val)
	return len(idx.GetRid(key, tx)) != 0
}

func (idx *Index) convert(val interface{}) []byte {
	var vData []byte
	switch idx.ValType {
	case "string":
		str := val.(string)
		if !idx.CaseSensitive {
			str = strings.ToLower(str)
		}
		vData = []byte(str)

	case "boolean":
		b := val.(bool)
		if b {
			vData = []byte{1}
		} else {
			vData = []byte{0}
		}

	case "binary", "reference":
		vData = []byte(val.(string))

	case "integer":
		vData = utils.Itob(val.(int64))

	case "datetime":
		// the time will be in milliseconds stored in int64
		vData = utils.Itob(val.(int64))

	case "decimal":
		vData = utils.Ftob(val.(float64))

	default:
		panic(fmt.Errorf("invalid index data type %s given for index %s", idx.ValType, idx.Name))
	}

	return vData
}

func Open(path string, serverId uint16, config *conf.DomainConfig, rtypes map[string]*schema.ResourceType, sm map[string]*schema.Schema) (*Silo, error) {
	prvConf = config
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	sl := &Silo{}
	sl.db = db
	sl.resources = make(map[string][]byte)
	sl.indices = make(map[string]map[string]*Index)
	sl.sysIndices = make(map[string]map[string]*Index)
	sl.schemas = sm
	sl.resTypes = rtypes

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_RESOURCES)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_INDICES)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_WEBAUTHN)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Criticalf("Errors while opening the silo %s", err.Error())
		return nil, err
	}

	newIndices := make([]string, 0)

	for _, rt := range rtypes {

		var rc *conf.ResourceConf
		for _, v := range config.Resources {
			if v.Name == rt.Name {
				rc = v
				break
			}
		}

		if rc == nil {
			log.Infof("No additional configuration is present for ResourceType %s, configuring it with defaults", rt.Name)
		} else {
			log.Infof("Using additional configuration of ResourceType %s", rc.Name)
		}

		err = sl.createResourceBucket(rt)
		if err != nil {
			return nil, err
		}

		// the unique attributes should always be indexed
		// this helps in faster insertion time checks on uniqueness of attributes
		// we should not allow attribute name collisions in schemas
		indexFields := rt.UniqueAts

		if rc != nil {
			indexFields = append(indexFields, rc.IndexFields...)
		}

		// make sure not to create duplicate indices
		createdIdxNameMap := make(map[string]int)
		for _, idxName := range indexFields {
			at := rt.GetAtType(idxName)
			if at == nil {
				log.Warningf("There is no attribute with the name %s, index is not created", idxName)
				continue
			}

			key := strings.ToLower(idxName)
			if _, ok := createdIdxNameMap[key]; ok {
				continue
			}
			createdIdxNameMap[key] = 1

			resIdxMap := sl.indices[rt.Name]
			isNewIndex, idx, err := sl.createIndexBucket(rt.Name, idxName, at, false, resIdxMap)
			if err != nil {
				return nil, err
			}

			if isNewIndex {
				newIndices = append(newIndices, idx.Name)
			}
		}

		// create presence system index
		sysIdxMap := sl.sysIndices[rt.Name]

		prAt := &schema.AttrType{Description: "Virtual attribute type for presence index"}
		prAt.CaseExact = false
		prAt.MultiValued = true
		prAt.Type = "string"

		_, _, err := sl.createIndexBucket(rt.Name, "presence", prAt, true, sysIdxMap)
		if err != nil {
			return nil, err
		}
	}

	// delete the unused resource or index buckets and initialize the counts of the indices and resources
	err = sl.db.Update(func(tx *bolt.Tx) error {

		bucket := tx.Bucket(BUC_RESOURCES)
		bucket.ForEach(func(k, v []byte) error {
			resName := string(k)
			_, present := sl.resources[resName]
			if !present {
				log.Infof("Deleting unused bucket of resource %s", resName)
				bucket.Delete(k)
				tx.DeleteBucket(k)
			}

			return nil
		})

		bucket = tx.Bucket(BUC_INDICES)
		bucket.ForEach(func(k, v []byte) error {
			idxBName := string(k)
			tokens := strings.Split(idxBName, RES_INDEX_DELIM)
			resName := tokens[0]
			idxName := tokens[1]
			_, present := sl.indices[resName][idxName]
			if !present && !strings.HasSuffix(idxName, "_system") { // do not delete system indices
				log.Infof("Deleting unused bucket of index %s of resource %s", idxName, resName)
				bucket.Delete(k)
				tx.DeleteBucket(k)
			}

			return nil
		})

		return err
	})

	sl.Engine = rbac.NewEngine()

	sl.cg = base.NewCsnGenerator(serverId)
	// load the roles
	sl.LoadGroups()

	return sl, nil
}

func (sl *Silo) Close() {
	log.Infof("Closing resource silo")
	sl.db.Close()
}

func (sl *Silo) createResourceBucket(rc *schema.ResourceType) error {
	data := []byte(rc.Name)

	err := sl.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket(data)

		if err == nil {
			log.Infof("Creating bucket for resource %s", rc.Name)
			bucket := tx.Bucket(BUC_RESOURCES)
			err = bucket.Put(data, []byte(nil))
		}

		if err == bolt.ErrBucketExists {
			err = nil
		}

		return err
	})

	if err == nil {
		sl.resources[rc.Name] = data
		sl.indices[rc.Name] = make(map[string]*Index)
		sl.sysIndices[rc.Name] = make(map[string]*Index)
	}

	return err
}

func (sl *Silo) createIndexBucket(resourceName, attrName string, at *schema.AttrType, sysIdx bool, resIdxMap map[string]*Index) (bool, *Index, error) {
	iName := strings.ToLower(attrName)
	bname := resourceName + RES_INDEX_DELIM + iName
	if sysIdx {
		bname = bname + "_system"
	}

	bnameBytes := []byte(bname)

	idx := &Index{}
	idx.Name = iName
	idx.Bname = bname
	idx.BnameBytes = bnameBytes
	idx.CaseSensitive = at.CaseExact
	idx.ValType = at.Type
	// parent's singularity applies for complex attributes
	// fixme only unique natured attribute's indices are not multi-valued rest all should allow dupkey
	//if at.Parent() != nil {
	//	idx.AllowDupKey = at.Parent().MultiValued
	//} else {
	//	idx.AllowDupKey = at.MultiValued
	//}
	if !at.IsUnique() {
		idx.AllowDupKey = true
	}
	idx.db = sl.db

	var isNewIndex bool

	err := sl.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket(bnameBytes)

		if err == bolt.ErrBucketExists {
			err = nil
		}

		if err == nil {
			log.Infof("Creating bucket for index %s of resource %s", attrName, resourceName)
			bucket := tx.Bucket(BUC_INDICES)

			// now store the index
			var buf bytes.Buffer

			enc := gob.NewEncoder(&buf)
			err = enc.Encode(idx)
			if err == nil {
				bucket.Put(bnameBytes, buf.Bytes())
				isNewIndex = true
			}
		}

		return err
	})

	if err == nil {
		resIdxMap[idx.Name] = idx
	}

	return isNewIndex, idx, err
}

func fillResourceMap(bucket *bolt.Bucket, m map[string][]byte) error {
	err := bucket.ForEach(func(k, v []byte) error {
		key := string(k)
		value := make([]byte, len(k))
		copy(value, k)
		m[key] = value
		return nil
	})

	return err
}

func fillIndexMap(bucket *bolt.Bucket, m map[string]*Index) error {
	err := bucket.ForEach(func(k, v []byte) error {
		name := string(k)
		nameBytes := make([]byte, len(k))
		copy(nameBytes, k)

		buf := bytes.NewBuffer(v)
		dec := gob.NewDecoder(buf)
		var idx Index
		err := dec.Decode(&idx)
		if err == nil {
			m[name] = &idx
		}

		return nil
	})

	return err
}

func (sl *Silo) Insert(crCtx *base.CreateContext) (err error) {
	crCtx.InRes.RemoveReadOnlyAt()

	rid := utils.GenUUID()
	crCtx.InRes.SetId(rid)

	return sl.InsertInternal(crCtx)
}

func (sl *Silo) InsertInternal(crCtx *base.CreateContext) (err error) {
	inRes := crCtx.InRes
	if !crCtx.Repl {
		err = inRes.CheckMissingRequiredAts()
		if err != nil {
			return err
		}
	}

	rid := inRes.GetId()

	// validate the uniqueness constraints based on the schema
	rt := inRes.GetType()

	tx, err := sl.db.Begin(true)

	isGroup := false

	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for inserting the resource [%s]", err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return err
	}

	sl.mutex.Lock()

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			log.Debugf("failed to insert %s resource [%s]", rt.Name, err)
		} else {
			tx.Commit()

			if isGroup {
				sl.Engine.UpsertRole(inRes, sl.resTypes)
			}

			log.Debugf("Successfully inserted resource with id %s", rid)
		}

		sl.mutex.Unlock()
	}()

	if !crCtx.Repl {
		// now, add meta attribute
		inRes.AddMeta(sl.cg.NewCsn())
	}

	//log.Debugf("checking unique attributes %s", rt.UniqueAts)
	//log.Debugf("indices map %#v", sl.indices[rtName])
	/*for _, name := range rt.UniqueAts {
		// check if the value has already been used
		attr := inRes.GetAttr(name)
		if attr == nil {
			continue
		}
		idx := sl.indices[rt.Name][name]
	}*/

	prIdx := sl.getSysIndex(rt.Name, "presence")

	for name, idx := range sl.indices[rt.Name] {
		attr := inRes.GetAttr(name)
		if attr == nil {
			continue
		}

		atType := attr.GetType()
		if attr.IsSimple() && atType.IsUnique() {
			sa := attr.GetSimpleAt()
			for _, val := range sa.Values {
				log.Tracef("checking unique attribute %#v", idx)
				if idx.HasVal(val, tx) {
					detail := fmt.Sprintf("Uniqueness violation, value %s of attribute %s already exists", val, sa.Name)
					err := base.NewConflictError(detail)
					err.ScimType = base.ST_UNIQUENESS
					panic(err)
				} else {
					err := idx.add(val, rid, tx)
					if err != nil {
						panic(err)
					}
				}
			}

			if name != "id" { // do not add resource's id attribute - that will just blow up the index unnecessarily
				err := prIdx.add(name, rid, tx) // do not add sa.Name that will lose the attribute path
				if err != nil {
					panic(err)
				}
			}
			continue
		}

		parentType := atType.Parent()
		if parentType != nil { //&& parentType.MultiValued
			parentAt := inRes.GetAttr(strings.ToLower(parentType.Name))
			ca := parentAt.GetComplexAt()
			atName := strings.ToLower(atType.Name) // the sub-attribute's name
			for _, smap := range ca.SubAts {
				if at, ok := smap[atName]; ok {
					addToIndex(name, at.GetSimpleAt(), rid, idx, prIdx, tx)
				}
			}
		} else {
			sa := attr.GetSimpleAt()
			addToIndex(name, sa, rid, idx, prIdx, tx)
		}
	}

	if rt.Name == "Group" {
		isGroup = true
		members := inRes.GetAttr("members")
		if members != nil {
			displayName := inRes.GetAttr("displayname").GetSimpleAt().GetStringVal()
			ca := members.GetComplexAt()
			sl.addGroupMembers(ca, rid, displayName, tx)
		}
	}

	// for User resource initialize AuthData
	if rt.Name == "User" {
		if !crCtx.Repl {
			inRes.AuthData = &base.AuthData{}
		} else {
			wid := inRes.AuthData.WebauthnId
			if wid != "" {
				tx.Bucket(BUC_WEBAUTHN).Put([]byte(wid), []byte(rid))
			}
		}
	}

	sl.storeResource(tx, inRes)

	return nil
}

func (sl *Silo) addGroupMembers(members *base.ComplexAttribute, groupRid string, displayName string, tx *bolt.Tx) {
	groupType := sl.resTypes["Group"]
	gRefAtType := groupType.GetAtType("members.$ref")
	gTypeAtType := groupType.GetAtType("members.type")

	ugroupIdx := sl.getIndex("User", "groups.value")

	for _, subAtMap := range members.SubAts {
		value := subAtMap["value"]
		if value != nil {
			refId := value.Values[0].(string)
			refType := subAtMap["type"]

			refTypeVal := "User" // default value
			if refType != nil {
				refTypeVal = refType.Values[0].(string)
			} else {
				log.Debugf("No reference type is mentioned, assuming the default value %s", refTypeVal)
			}

			refRType := sl.resTypes[refTypeVal]
			if refRType == nil {
				detail := fmt.Sprintf("Resource type %s is not found(it was associated with the resource ID %s in the input)", refTypeVal, refId)
				panic(base.NewNotFoundError(detail))
			}

			refRes, _ := sl.getUsingTx(refId, refRType, tx)

			if refRes == nil {
				detail := fmt.Sprintf("There is no resource of type %s with the referenced value %s", refTypeVal, refId)
				panic(base.NewNotFoundError(detail))
			}

			// update the $ref and type values in the Group's "members" attribute
			subAtMap["$ref"] = base.NewSimpleAt(gRefAtType, refRType.Endpoint+"/"+refRes.GetId())
			subAtMap["type"] = base.NewSimpleAt(gTypeAtType, refRType.Name)

			if refRType.Name == "User" {
				updated := sl.addGroupToUser(refRes, groupRid, displayName)
				if updated {
					ugroupIdx.add(groupRid, refId, tx)
					//refRes.UpdateLastModTime(sl.cg.NewCsn())
					sl.storeResource(tx, refRes)
				}
			}
		}
	}
}

func (sl *Silo) addGroupToUser(refRes *base.Resource, groupRid string, groupDisplayName string) bool {
	groups := refRes.GetAttr("groups")
	subAt := make(map[string]interface{})
	subAt["value"] = groupRid
	subAt["$ref"] = "/Groups/" + groupRid
	subAt["type"] = "Group"
	subAt["display"] = groupDisplayName

	updated := false
	if groups == nil {
		err := refRes.AddCA("groups", subAt)
		if err != nil {
			panic(err)
		}
		updated = true
	} else {
		ca := groups.GetComplexAt()
		present := false
		// add only if the group is not already present in this user
		for _, groupAtMap := range ca.SubAts {
			existingGid := groupAtMap["value"].Values[0].(string)
			if existingGid == groupRid {
				present = true
				break
			}
		}

		if !present {
			ca.AddSubAts(subAt)
			updated = true
		}
	}

	return updated
}

// FIXME there is a method duplicating this functionality in addSAtoIndex() in silo_patch.go
func addToIndex(atPath string, sa *base.SimpleAttribute, rid string, idx *Index, prIdx *Index, tx *bolt.Tx) {
	for _, val := range sa.Values {
		err := idx.add(val, rid, tx)
		if err != nil {
			panic(err)
		}
	}

	err := prIdx.add(atPath, rid, tx) // do not add sa.Name that will lose the attribute path
	if err != nil {
		detail := fmt.Sprintf("error while adding attribute %s into presence index %s", atPath, err.Error())
		panic(base.NewInternalserverError(detail))
	}

}

func (sl *Silo) GetUser(rid string) (resource *base.Resource, err error) {
	return sl.Get(rid, sl.resTypes["User"])
}

func (sl *Silo) Get(rid string, rt *schema.ResourceType) (resource *base.Resource, err error) {
	tx, err := sl.db.Begin(false)
	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for fetching the resource [%s]", err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return nil, err
	}

	defer tx.Rollback()

	return sl.getUsingTx(rid, rt, tx)
}

func (sl *Silo) getUsingTx(rid string, rt *schema.ResourceType, tx *bolt.Tx) (resource *base.Resource, err error) {
	ridBytes := []byte(rid)
	rtNameBytes := sl.resources[rt.Name]

	buck := tx.Bucket(rtNameBytes)

	resData := buck.Get(ridBytes)
	if resData != nil {
		reader := bytes.NewReader(resData)
		decoder := gob.NewDecoder(reader)
		err = decoder.Decode(&resource)
	}

	if err != nil {
		return nil, err
	}

	if resource != nil {
		resource.SetSchema(rt)
	} else {
		detail := fmt.Sprintf("%s with ID %s not found", rt.Name, rid)
		err = base.NewNotFoundError(detail)
	}

	return resource, err
}

func (sl *Silo) Delete(delCtx *base.DeleteContext) (err error) {
	rid := delCtx.Rid
	rt := delCtx.Rt
	tx, err := sl.db.Begin(true)
	if err != nil {
		return err
	}

	sl.mutex.Lock()

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			log.Debugf("failed to remove resource with ID %s %#v", rid, err)
			tx.Rollback()
		} else {
			tx.Commit()

			if rt.Name == "Group" {
				sl.Engine.DeleteRole(rid)
			}

			log.Debugf("Successfully removed resource with ID %s", rid)
		}

		sl.mutex.Unlock()
	}()

	err = sl._removeResource(rid, rt, tx)

	if err == nil {
		delCtx.DeleteCsn = sl.cg.NewCsn().String()
	}

	return err
}

func (sl *Silo) _removeResource(rid string, rt *schema.ResourceType, tx *bolt.Tx) (err error) {
	ridBytes := []byte(rid)
	rtNameBytes := sl.resources[rt.Name]

	buck := tx.Bucket(rtNameBytes)
	resData := buck.Get(ridBytes)
	if len(resData) == 0 {
		return base.NewNotFoundError(rt.Name + " resource with ID " + rid + " not found")
	}

	var resource *base.Resource

	reader := bytes.NewReader(resData)
	decoder := gob.NewDecoder(reader)
	err = decoder.Decode(&resource)

	if err != nil {
		return err
	}

	if resource != nil {
		resource.SetSchema(rt)
	}

	for name, idx := range sl.indices[rt.Name] {
		attr := resource.GetAttr(name)
		if attr == nil {
			continue
		}
		if attr.IsSimple() {
			sa := attr.GetSimpleAt()
			for _, val := range sa.Values {
				err := idx.remove(val, rid, tx)
				if err != nil {
					panic(err)
				}
			}
		}
	}

	if rt.Name == "Group" {
		members := resource.GetAttr("members")
		if members != nil {
			ca := members.GetComplexAt()
			for _, subAtMap := range ca.SubAts {
				refType := subAtMap["type"].Values[0].(string)
				refId := subAtMap["value"].Values[0].(string)
				refRt := sl.resTypes[refType]

				// handle nested groups
				if refType == "Group" {
					err := sl._removeResource(refId, refRt, tx)
					if err != nil {
						return err
					}
				} else if refType == "User" {
					ugroupIdx := sl.getIndex(refType, "groups.value")
					res, _ := sl.getUsingTx(refId, refRt, tx)
					if res != nil {
						groups := res.GetAttr("groups").GetComplexAt()
						for i, gatMap := range groups.SubAts {
							val := gatMap["value"].Values[0].(string)
							if val == rid {
								delete(groups.SubAts, i)
								if len(groups.SubAts) == 0 {
									res.DeleteAttr("groups")
								}

								if ugroupIdx != nil {
									ugroupIdx.remove(val, refId, tx)
								}
								//res.UpdateLastModTime(sl.cg.NewCsn())
								sl.storeResource(tx, res)
								break
							}
						}
					}
				}
			}
		}
	} else if rt.Name == "User" {
		groups := resource.GetAttr("groups")
		if groups != nil {
			refRt := sl.resTypes["Group"]
			gmemberIdx := sl.getIndex(refRt.Name, "members.value")
			ca := groups.GetComplexAt()
			for _, subAtMap := range ca.SubAts {
				// the ID of the group
				gid := subAtMap["value"].Values[0].(string)
				res, _ := sl.getUsingTx(gid, refRt, tx)
				members := res.GetAttr("members").GetComplexAt()
				for i, memMap := range members.SubAts {
					val := memMap["value"].Values[0].(string)
					if val == rid {
						delete(members.SubAts, i)
						if gmemberIdx != nil {
							// removing
							gmemberIdx.remove(rid, gid, tx)
						}
						//res.UpdateLastModTime(sl.cg.NewCsn())
						sl.storeResource(tx, res)
						break
					}
				}
			}
		}
		wid := resource.AuthData.WebauthnId
		if wid != "" {
			err := tx.Bucket(BUC_WEBAUTHN).Delete([]byte(wid))
			if err != nil {
				return err
			}
		}
	}

	err = buck.Delete(ridBytes)

	if err != nil {
		return err
	}

	return nil
}

func (sl *Silo) storeResource(tx *bolt.Tx, res *base.Resource) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(res)

	if err != nil {
		detail := fmt.Sprintf("Failed to encode resource %s", err)
		log.Warningf(detail)
		panic(base.NewInternalserverError(detail))
	}

	resBucket := tx.Bucket(sl.resources[res.GetType().Name])
	err = resBucket.Put([]byte(res.GetId()), buf.Bytes())
	if err != nil {
		panic(err)
	}
}

func (sl *Silo) Replace(replaceCtx *base.ReplaceContext) (err error) {
	inRes := replaceCtx.InRes
	version := replaceCtx.IfMatch
	err = inRes.CheckMissingRequiredAts()
	if err != nil {
		return err
	}

	//inRes.RemoveReadOnlyAt()

	rid := inRes.GetId()

	if len(rid) == 0 {
		return base.NewBadRequestError("id attribute is missing")
	}

	// validate the uniqueness constraints based on the schema
	rt := inRes.GetType()

	tx, err := sl.db.Begin(true)

	isGroup := false

	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for replacing the resource [%s]", err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return err
	}

	sl.mutex.Lock()

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			replaceCtx.Res = nil
			log.Debugf("failed to replace %s resource [%s]", rt.Name, err)
		} else {
			tx.Commit()
			if isGroup {
				sl.Engine.UpsertRole(inRes, sl.resTypes)
			}

			log.Debugf("Successfully replaced resource with id %s", rid)
		}

		sl.mutex.Unlock()
	}()

	existing, err := sl.getUsingTx(rid, rt, tx)

	if err != nil {
		return err
	}

	if replaceCtx.Repl {
		if !replaceCtx.Cloning {
			curVersion := existing.GetVersion()
			if strings.Compare(curVersion, replaceCtx.ReplVersion) > 0 {
				return fmt.Errorf("replication event is older than the current version %s of the target resource %s, aborting replace", curVersion, rid)
			}
		}
	} else if strings.Compare(existing.GetVersion(), version) != 0 {
		msg := fmt.Sprintf("The given version %s of the resource %s doesn't match with stored version", version, rid)
		log.Debugf(msg)
		return base.NewPreCondError(msg)
	}

	prIdx := sl.getSysIndex(rt.Name, "presence")

	if rt.Name == "Group" {
		isGroup = true
		var inMembers, existingMembers *base.ComplexAttribute
		inMemAt := inRes.GetAttr("members")
		if inMemAt != nil {
			inMembers = inMemAt.GetComplexAt()
		}

		exMemAt := existing.GetAttr("members")
		if exMemAt != nil {
			existingMembers = exMemAt.GetComplexAt()
		}

		// compute refIds to be added or to be deleted and based on that perform the action
		if inMembers == nil {
			if existingMembers != nil {
				sl.deleteGroupMembers(existingMembers, rid, tx)
			}
		} else {
			sl.deleteGroupMembers(existingMembers, rid, tx)
			displayName := inRes.GetAttr("displayname").GetSimpleAt().GetStringVal()
			sl.addGroupMembers(inMembers, rid, displayName, tx)
		}
	}

	sl.replaceAtGroup(rt.Name, rid, tx, prIdx, inRes.Core, existing.Core)

	if len(inRes.Ext) == 0 {
		for _, exExt := range existing.Ext {
			// drop all the attributes of this extended schema object from indices
			sl.deleteFromAtGroup(rt.Name, rid, tx, prIdx, nil, exExt)
		}
		// finally make the Ext map empty
		existing.Ext = make(map[string]*base.AtGroup)
	} else {
		for scId, inExt := range inRes.Ext {
			exExt := existing.Ext[scId]
			if exExt == nil {
				exExt = base.NewAtGroup()
				existing.Ext[scId] = exExt
			}
			// now index all the attributes in this extended schema object
			sl.replaceAtGroup(rt.Name, rid, tx, prIdx, inExt, exExt)
		}

		// now delete those extensions that are not present in the incoming resource
		for scId, exExt := range existing.Ext {
			if _, ok := inRes.Ext[scId]; !ok {
				sl.deleteFromAtGroup(rt.Name, rid, tx, prIdx, nil, exExt)
				delete(existing.Ext, scId)
			}
		}
	}

	// delete the non-asserted Core attributes
	sl.deleteFromAtGroup(rt.Name, rid, tx, prIdx, inRes.Core, existing.Core)

	if replaceCtx.Repl {
		// update the version with the given value
		meta := existing.GetMeta().GetFirstSubAt()
		meta["version"].Values[0] = replaceCtx.ReplVersion
	} else {
		// update last modified time
		existing.UpdateLastModTime(sl.cg.NewCsn())
	}
	existing.UpdateSchemas()

	sl.storeResource(tx, existing)
	replaceCtx.Res = existing
	return nil
}

func (sl *Silo) deleteGroupMembers(existingMembers *base.ComplexAttribute, groupRid string, tx *bolt.Tx) bool {
	if existingMembers == nil {
		return false
	}

	updated := false
	for _, subAtMap := range existingMembers.SubAts {
		tmp := sl._deleteGroupMembers(subAtMap, groupRid, tx)
		if !updated {
			updated = tmp
		}
	}

	return updated
}

func (sl *Silo) _deleteGroupMembers(memberSubAtMap map[string]*base.SimpleAttribute, groupRid string, tx *bolt.Tx) bool {
	refId := memberSubAtMap["value"].Values[0].(string)
	refType := "User"
	refTypeAt := memberSubAtMap["type"]
	if refTypeAt != nil {
		refType = refTypeAt.Values[0].(string)
	}

	refRt := sl.resTypes[refType]
	if refType == "User" {
		ugroupIdx := sl.getIndex(refType, "groups.value")
		user, _ := sl.getUsingTx(refId, refRt, tx)
		if user != nil {
			updated := false
			groups := user.GetAttr("groups").GetComplexAt()

			for key, subAtMap := range groups.SubAts {
				userGroupId := subAtMap["value"].Values[0].(string)
				if userGroupId == groupRid {
					if ugroupIdx != nil {
						uid := user.GetId()
						ugroupIdx.remove(groupRid, uid, tx)
					}
					delete(groups.SubAts, key)
					updated = true
				}
			}

			if updated {
				if len(groups.SubAts) == 0 {
					user.DeleteAttr("groups")
				}
				//user.UpdateLastModTime(sl.cg.NewCsn())
				sl.storeResource(tx, user)
				return updated
			}
		}
	}

	return false
}

func (sl *Silo) deleteFromAtGroup(resName string, rid string, tx *bolt.Tx, prIdx *Index, inAtg *base.AtGroup, exAtg *base.AtGroup) {
	for name, sa := range exAtg.SimpleAts {
		atType := sa.GetType()

		if atType.IsReadOnly() || atType.IsImmutable() {
			continue
		}

		var inAt *base.SimpleAttribute
		if inAtg != nil {
			inAt = inAtg.SimpleAts[name]
		}
		if inAt == nil {
			delete(exAtg.SimpleAts, name)
			idx := sl.getIndex(resName, name)
			if idx != nil {
				prIdx.remove(name, rid, tx)
				for _, val := range sa.Values {
					err := idx.remove(val, rid, tx)
					if err != nil {
						panic(err)
					}
				}
			}

		}
	}

	for name, ca := range exAtg.ComplexAts {
		atType := ca.GetType()

		if atType.IsReadOnly() || atType.IsImmutable() {
			continue
		}

		var inAt *base.ComplexAttribute
		if inAtg != nil {
			inAt = inAtg.ComplexAts[name]
		}

		if inAt == nil {
			delete(exAtg.ComplexAts, name)

			for _, saMap := range ca.SubAts {
				for _, sa := range saMap {
					atPath := name + "." + sa.Name
					idx := sl.getIndex(resName, atPath)
					if idx != nil {
						err := prIdx.remove(atPath, rid, tx)
						if err != nil {
							panic(err)
						}

						for _, val := range sa.Values {
							err := idx.remove(val, rid, tx)
							if err != nil {
								panic(err)
							}

						}
					}
				}
			}
		}
	}
}

func (sl *Silo) replaceAtGroup(resName string, rid string, tx *bolt.Tx, prIdx *Index, inAtg *base.AtGroup, exAtg *base.AtGroup) {
	for name, sa := range inAtg.SimpleAts {
		atType := sa.GetType()

		if atType.IsReadOnly() {
			continue
		}

		exAt := exAtg.SimpleAts[name]

		var replaced *base.SimpleAttribute

		if atType.IsImmutable() {
			if exAt != nil {
				if !sa.Equals(exAt) {
					detail := fmt.Sprintf("Incoming value doesn't match with the existing value of immutable attribute %s", name)
					se := base.NewBadRequestError(detail)
					se.ScimType = base.ST_MUTABILITY
					panic(se)
				}
			} else {
				// add the immutable
				replaced = exAtg.SimpleAts[name]
				exAtg.SimpleAts[name] = sa
			}
		} else {
			if !sa.Equals(exAt) {
				replaced = exAtg.SimpleAts[name]
				exAtg.SimpleAts[name] = sa
			}
		}

		idx := sl.getIndex(resName, sa.Name)
		if idx != nil {
			if replaced != nil {
				for _, val := range replaced.Values {
					err := prIdx.remove(sa.Name, rid, tx)
					if err != nil {
						panic(err)
					}

					err = idx.remove(val, rid, tx)
					if err != nil {
						panic(err)
					}

				}
			}

			for _, val := range sa.Values {
				err := prIdx.add(sa.Name, rid, tx)
				if err != nil {
					panic(err)
				}

				err = idx.add(val, rid, tx)
				if err != nil {
					panic(err)
				}
			}
		}
	}

	for name, ca := range inAtg.ComplexAts {
		atType := ca.GetType()

		if atType.IsReadOnly() || atType.IsImmutable() {
			continue
		}

		exAt := exAtg.ComplexAts[name]

		// there is no way to identify the equality when it is multivalued, just overwrite it
		sl.dropCAtFromIndex(exAt, prIdx, resName, rid, tx)

		exAtg.ComplexAts[name] = ca
		// index them now
		sl.addCAtoIndex(ca, prIdx, resName, rid, tx)
	}
}

//TODO add  cancel channel to stop processing when the http client is closed
func (sl *Silo) Search(sc *base.SearchContext, outPipe chan *base.Resource) error {
	tx, err := sl.db.Begin(false)
	if err != nil {
		panic(err)
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			if log.IsDebugEnabled() {
				log.Debugf("Error while searching for resources %s", err.Error())
				debug.PrintStack()
			}
		}

		close(outPipe)
		tx.Rollback()
	}()

	candidates := make(map[string]*base.Resource)

	for _, rsType := range sc.ResTypes {
		count := getOptimizedResults(sc.Filter, rsType, tx, sl, candidates)
		evaluator := base.BuildEvaluator(sc.Filter)

		buc := tx.Bucket(sl.resources[rsType.Name])

		if count < math.MaxInt64 {
			for k, _ := range candidates {
				data := buc.Get([]byte(k))
				reader := bytes.NewReader(data)
				decoder := gob.NewDecoder(reader)

				if data != nil {
					var rs *base.Resource
					err = decoder.Decode(&rs)
					if err != nil {
						panic(err)
					}

					rs.SetSchema(rsType)
					if evaluator.Evaluate(rs) {
						outPipe <- rs
					}
				}
			}
		} else {
			log.Debugf("Scanning complete DB of %s for search results", rsType.Name)
			cursor := buc.Cursor()

			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				reader := bytes.NewReader(v)
				decoder := gob.NewDecoder(reader)

				if v != nil {
					var rs *base.Resource
					err = decoder.Decode(&rs)
					if err != nil {
						panic(err)
					}

					rs.SetSchema(rsType)
					if evaluator.Evaluate(rs) {
						outPipe <- rs
					}
				}
			}
		}
	}

	return nil
}

// intended for internal use only, must NOT be used for filters that return large number of resources
func (sl *Silo) FindResources(filter *base.FilterNode, rt *schema.ResourceType) []*base.Resource {
	tx, err := sl.db.Begin(false)
	if err != nil {
		panic(err)
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			if log.IsDebugEnabled() {
				log.Debugf("Error while finding a resource %s", err.Error())
				debug.PrintStack()
			}
		}
		tx.Rollback()
	}()

	candidates := make(map[string]*base.Resource)
	count := getOptimizedResults(filter, rt, tx, sl, candidates)
	evaluator := base.BuildEvaluator(filter)

	buc := tx.Bucket(sl.resources[rt.Name])

	results := make([]*base.Resource, 0)

	if count < math.MaxInt64 {
		for k, _ := range candidates {
			data := buc.Get([]byte(k))
			reader := bytes.NewReader(data)
			decoder := gob.NewDecoder(reader)

			if data != nil {
				var rs *base.Resource
				err = decoder.Decode(&rs)
				if err != nil {
					panic(err)
				}

				rs.SetSchema(rt)
				if evaluator.Evaluate(rs) {
					results = append(results, rs)
				}
			}
		}
	} else {
		log.Debugf("Scanning complete DB of %s to find resources by filter", rt.Name)
		cursor := buc.Cursor()

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			reader := bytes.NewReader(v)
			decoder := gob.NewDecoder(reader)

			if v != nil {
				var rs *base.Resource
				err = decoder.Decode(&rs)
				if err != nil {
					panic(err)
				}

				rs.SetSchema(rt)
				if evaluator.Evaluate(rs) {
					results = append(results, rs)
				}
			}
		}
	}

	return results
}

func (sl *Silo) ReadAllOfType(rt *schema.ResourceType, outPipe chan *base.Resource) error {
	tx, err := sl.db.Begin(false)
	if err != nil {
		panic(err)
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			if log.IsDebugEnabled() {
				log.Debugf("Error while reading resources of type %s [%#v]", rt.Name, err.Error())
				debug.PrintStack()
			}
		}

		close(outPipe)
		tx.Rollback()
	}()

	log.Debugf("Reading all resources of type %s", rt.Name)
	buc := tx.Bucket(sl.resources[rt.Name])
	cursor := buc.Cursor()

	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		reader := bytes.NewReader(v)
		decoder := gob.NewDecoder(reader)

		if v != nil {
			var rs *base.Resource
			err = decoder.Decode(&rs)
			if err != nil {
				panic(err)
			}

			rs.SetSchema(rt)
			outPipe <- rs
		}
	}

	return nil
}

func (sl *Silo) LoadGroups() {
	tx, err := sl.db.Begin(false)

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			log.Debugf("Error while loading groups %s", err.Error())
		}

		tx.Rollback()
	}()

	if err != nil {
		panic(err)
	}

	log.Debugf("Loading Groups")
	groupType := sl.resTypes["Group"]
	buc := tx.Bucket(sl.resources[groupType.Name])
	cursor := buc.Cursor()

	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		reader := bytes.NewReader(v)
		decoder := gob.NewDecoder(reader)

		if v != nil {
			var rs *base.Resource
			err = decoder.Decode(&rs)
			if err != nil {
				panic(err)
			}

			rs.SetSchema(groupType)
			sl.Engine.UpsertRole(rs, sl.resTypes)
		}
	}

}

func (sl *Silo) GetUserByName(username string) (user *base.Resource, err error) {
	rt := sl.resTypes["User"]
	idx := sl.getIndex(rt.Name, "username")

	tx, err := sl.db.Begin(false)
	if err != nil {
		return nil, err
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			log.Debugf("Error while fetching the user with username %s %#v", username, err)
		}

		tx.Rollback()
	}()

	rid := idx.GetRid(idx.convert(username), tx)

	if len(rid) == 0 {
		return nil, fmt.Errorf("User with username %s not found", username)
	}

	user, err = sl.getUsingTx(rid, rt, tx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (sl *Silo) StoreTotpSecret(rid string, totpSecret string) error {
	tx, err := sl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to begin transaction %#v", err)
		return err
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			log.Debugf("Error while storing TOTP secret %#v", err)
		} else {
			tx.Commit()
		}
	}()

	rt := sl.resTypes["User"]
	user, err := sl.getUsingTx(rid, rt, tx)
	if err != nil {
		return err
	}

	user.AuthData.TotpSecret = totpSecret
	user.AuthData.TotpCodes = nil

	user.UpdateLastModTime(sl.cg.NewCsn())
	sl.storeResource(tx, user)

	return nil
}

func (sl *Silo) Authenticate(principal string, password string) (lr base.LoginResult, err error) {
	pos := strings.IndexRune(principal, '/')
	if pos > 0 {
		principal = principal[0:pos]
	}

	lr = base.LoginResult{}

	rt := sl.resTypes["User"]
	idx := sl.getIndex(rt.Name, "username")

	tx, err := sl.db.Begin(true)
	if err != nil {
		return lr, err
	}

	defer func() {
		e := recover()
		// panic error
		var pErr error
		if e != nil {
			pErr = e.(error)
		}

		if pErr != nil {
			tx.Rollback()
			err = pErr
			log.Warningf("Error while authenticating principal %s %#v", principal, pErr)
		} else {
			// commit the changes made to AuthData
			tx.Commit()
		}
	}()

	rid := idx.GetRid(idx.convert(principal), tx)

	if len(rid) == 0 {
		lr.Status = base.LOGIN_USER_NOT_FOUND
		return lr, fmt.Errorf("User with principal %s not found", principal)
	}

	user, err := sl.getUsingTx(rid, rt, tx)
	if err != nil {
		lr.Status = base.LOGIN_USER_NOT_FOUND
		return lr, err
	}

	lr.Id = rid
	active := false
	activeAt := user.GetAttr("active")
	if activeAt != nil {
		active = activeAt.GetSimpleAt().Values[0].(bool)
	}

	ad := user.AuthData

	if !active {
		lr.Status = base.LOGIN_ACCOUNT_NOT_ACTIVE
		ad.LastFLogin = time.Now().UTC()
		ad.FLoginCount++
		err = base.NewForbiddenError("Account is not active")
	}

	skipAdUpdate := false
	tfaEn := user.IsTfaEnabled()
	if err == nil {
		at := user.GetAttr("password")
		if at == nil {
			lr.Status = base.LOGIN_NO_PASSWORD
			ad.LastFLogin = time.Now().UTC()
			ad.FLoginCount++
			err = fmt.Errorf("No password present for the user %s", principal)
		}

		if err == nil {
			hashedPasswd := at.GetSimpleAt().Values[0].(string)

			// compare passwords
			if utils.ComparePassword(password, hashedPasswd) {
				// update authdata in this case only if TFA is not enabled for the user
				if !tfaEn {
					if isChangePassword(user) {
						lr.Status = base.LOGIN_CHANGE_PASSWORD
					} else {
						lr.Status = base.LOGIN_SUCCESS
					}
					lr.User = user
					ad.LastSLogin = time.Now().UTC()
					ad.FLoginCount = 0
					err = nil
				} else {
					skipAdUpdate = true
					if user.IsTfaSetupComplete() {
						lr.Status = base.LOGIN_TFA_REQUIRED
						err = fmt.Errorf("TFA code is required for the user %s", principal)
					} else {
						lr.Status = base.LOGIN_TFA_REGISTER
						err = fmt.Errorf("TFA registration is pending for the user %s", principal)
					}
				}
			} else {
				ad.LastFLogin = time.Now().UTC()
				ad.FLoginCount++
				err = fmt.Errorf("Invalid password, did not match")
			}

		}
	}

	// only needs to be updated either when authentication failed or when authentication was
	// successful and no TFA is enabled
	if !skipAdUpdate {
		user.UpdateLastModTime(sl.cg.NewCsn())
		sl.storeResource(tx, user)
	}

	return lr, err
}

func (sl *Silo) VerifyOtp(rid string, totpCode string) (lr base.LoginResult, err error) {
	rt := sl.resTypes["User"]

	lr = base.LoginResult{}
	lr.Id = rid
	tx, err := sl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to begin transaction %#v", err)
		return lr, err
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			log.Debugf("Error while validating OTP %#v", err)
		} else {
			// commit the changes made to AuthData
			tx.Commit()
		}
	}()

	user, err := sl.getUsingTx(rid, rt, tx)
	if err != nil {
		lr.Status = base.LOGIN_USER_NOT_FOUND
		log.Warningf("Failed to get user %#v", err)
		return lr, err
	}

	ad := user.AuthData
	validOtp := totp.Validate(totpCode, ad.TotpSecret)
	if !validOtp {
		// check in the recovery codes
		_, ok := ad.TotpCodes[totpCode]
		if ok {
			delete(ad.TotpCodes, totpCode)
			validOtp = true
		}
	}

	if validOtp {
		if isChangePassword(user) {
			lr.Status = base.LOGIN_CHANGE_PASSWORD
		} else {
			lr.Status = base.LOGIN_SUCCESS
		}
		lr.User = user
		ad.LastSLogin = time.Now().UTC()
		ad.FLoginCount = 0
	} else {
		lr.Status = base.LOGIN_FAILED
		ad.LastFLogin = time.Now().UTC()
		ad.FLoginCount++
	}

	// TODO should we update the last mod when OTP gets updated
	// I don't think so, commenting it out
	//user.UpdateLastModTime(sl.cg.NewCsn())
	sl.storeResource(tx, user)

	return lr, nil
}

func (sl *Silo) ModifyGroupsOfUser(mgur base.ModifyGroupsOfUserRequest) (res *base.Resource, err error) {
	tx, err := sl.db.Begin(true)

	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for adding user to groups [%s]", err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return nil, err
	}

	userId := mgur.UserRid
	sl.mutex.Lock()

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			res = nil
			log.Debugf("failed to add user %s to groups [%s]", userId, err)
		} else {
			tx.Commit()
			log.Debugf("Successfully updated resource with id %s", userId)
		}

		sl.mutex.Unlock()
	}()

	rtUser := sl.resTypes["User"]
	user, err := sl.getUsingTx(userId, rtUser, tx)
	if err != nil {
		return nil, err
	}

	if strings.Compare(user.GetVersion(), mgur.UserVersion) != 0 {
		msg := fmt.Sprintf("The given version %s of the user %s doesn't match with stored version", mgur.UserVersion, userId)
		log.Debugf(msg)
		return nil, base.NewPreCondError(msg)
	}

	added := false
	removed := false

	// groups that were fetched and modified during this transaction
	fetchedGroups := make(map[string]*base.Resource)
	if len(mgur.RemoveGids) > 0 {
		removed = sl.removeUserFromGroups(user, mgur.RemoveGids, fetchedGroups, tx)
	}

	if len(mgur.AddGids) > 0 {
		added = sl.addUserToGroups(user, mgur.AddGids, fetchedGroups, tx)
	}

	if added || removed {
		for _, group := range fetchedGroups {
			// now persist group immediately and user at the end of the loop
			//group.UpdateLastModTime(sl.cg.NewCsn())
			sl.storeResource(tx, group)
		}

		user.UpdateLastModTime(sl.cg.NewCsn())
		sl.storeResource(tx, user)
	}

	return user, nil
}

func (sl *Silo) addUserToGroups(user *base.Resource, gids []string, fetchedGroups map[string]*base.Resource, tx *bolt.Tx) (updated bool) {
	rt := sl.resTypes["Group"]
	atType := rt.GetAtType("members")
	userId := user.GetId()
	ugroupIdx := sl.getIndex(user.GetType().Name, "groups.value")
	for _, id := range gids {
		group := fetchedGroups[id]
		var err error
		if group == nil {
			group, err = sl.getUsingTx(id, rt, tx)
			if err != nil {
				continue
			}
			fetchedGroups[id] = group
		}

		membersAt := group.GetAttr("members")
		if membersAt == nil {
			group.AddComplexAt(base.NewComplexAt(atType))
			membersAt = group.GetAttr("members")
		}

		ca := membersAt.GetComplexAt()
		// if the group already has this user as a member then do not add
		if ca.HasValue(userId) {
			continue
		}

		subAt := make(map[string]interface{})
		subAt["value"] = userId
		subAt["$ref"] = "/Users/" + userId
		subAt["type"] = "User"
		ca.AddSubAts(subAt)
		displayName := group.GetAttr("displayname").GetSimpleAt().GetStringVal()
		sl.addGroupToUser(user, id, displayName)
		updated = true

		ugroupIdx.add(id, userId, tx)
	}

	return updated
}

func (sl *Silo) removeUserFromGroups(user *base.Resource, gids []string, fetchedGroups map[string]*base.Resource, tx *bolt.Tx) (updated bool) {
	userGroups := user.GetAttr("groups")
	if userGroups == nil {
		return false
	}

	rt := sl.resTypes["Group"]
	ugroupIdx := sl.getIndex(user.GetType().Name, "groups.value")
	userId := user.GetId()
	for _, id := range gids {
		group := fetchedGroups[id]
		var err error
		if group == nil {
			group, err = sl.getUsingTx(id, rt, tx)
			if err != nil {
				continue
			}
			fetchedGroups[id] = group
		}

		removed := group.RemoveMember(userId)

		if !removed {
			continue
		}

		user.RemoveMemberOf(id)
		updated = true

		ugroupIdx.remove(id, userId, tx)
	}

	return updated
}

func (sl *Silo) ChangePassword(cpContext *base.ChangePasswordContext) (err error) {
	tx, err := sl.db.Begin(true)

	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for changing user's password [%s]", err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return err
	}

	sl.mutex.Lock()

	rid := cpContext.Rid
	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			log.Debugf("failed to change password of user %s [%s]", rid, err)
		} else {
			tx.Commit()
			log.Debugf("Successfully changed password of user %s", rid)
		}

		sl.mutex.Unlock()
	}()

	newPassword := cpContext.NewPassword
	hashingAlgo := cpContext.HashAlgo

	rtUser := sl.resTypes["User"]
	user, err := sl.getUsingTx(rid, rtUser, tx)
	if err != nil {
		return err
	}

	newPassword = utils.HashPassword(newPassword, hashingAlgo)
	atType := rtUser.GetAtType("password")
	passwdAt := user.GetAttr(atType.NormName)
	if passwdAt == nil {
		user.AddSA(atType.NormName, newPassword)
	} else {
		passwdAt.GetSimpleAt().Values[0] = newPassword
	}

	cpType := rtUser.GetAtType("changepassword")
	cpAt := user.GetAttr(cpType.NormName)
	if cpAt != nil {
		cpAt.GetSimpleAt().Values[0] = false
	}

	user.UpdateLastModTime(sl.cg.NewCsn())
	sl.storeResource(tx, user)

	cpContext.Res = user
	return nil
}

func isChangePassword(user *base.Resource) bool {
	changePasswordAt := user.GetAttr("changepassword")
	cp := false
	if changePasswordAt != nil {
		cp = changePasswordAt.GetSimpleAt().Values[0].(bool)
	}

	return cp
}

func (sl *Silo) Csn() base.Csn {
	return sl.cg.NewCsn()
}

func (sl *Silo) GenWebauthnIdFor(userId string) (*base.Resource, error) {
	tx, err := sl.db.Begin(true)
	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for generating webauthn ID for the resource %s %#v", userId, err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return nil, err
	}

	generated := false
	// locking mutex is not needed for this operation

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			log.Debugf("failed to update user with ID %s %#v", userId, err)
			tx.Rollback()
		} else {
			if generated {
				tx.Commit()
			} else {
				tx.Rollback()
			}
		}
	}()

	wid := ""
	user, err := sl.getUsingTx(userId, sl.resTypes["User"], tx)
	if err == nil {
		wid = user.AuthData.WebauthnId
		if wid == "" {
			wid = base64.RawURLEncoding.EncodeToString(utils.Rand32())
			user.AuthData.WebauthnId = wid
			user.UpdateLastModTime(sl.cg.NewCsn())
			sl.storeResource(tx, user)
			tx.Bucket(BUC_WEBAUTHN).Put([]byte(wid), []byte(userId))
			generated = true
			log.Debugf("Successfully generated webauthn ID for user with ID %s", userId)
		} else {
			return nil, base.NewConflictError("webauthn ID already exists for the user")
		}
	}

	return user, err
}

func (sl *Silo) GetUserByWebauthnId(webauthnId string) (user *base.Resource, err error) {
	tx, err := sl.db.Begin(false)
	if err != nil {
		return nil, err
	}

	rt := sl.resTypes["User"]
	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			log.Debugf("Error while fetching the user with webauthn ID %s %#v", webauthnId, err)
		}

		tx.Rollback()
	}()

	rid := tx.Bucket(BUC_WEBAUTHN).Get([]byte(webauthnId))

	if len(rid) == 0 {
		return nil, fmt.Errorf("User with webauthn ID %s not found", webauthnId)
	}

	user, err = sl.getUsingTx(string(rid), rt, tx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (sl *Silo) DeleteSecurityKey(userId string, credentialId string) (*base.Resource, error) {
	tx, err := sl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to begin transaction for deleting securitykey %#v", err)
		return nil, err
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			log.Debugf("Error while deleting security key %#v", err)
		} else {
			tx.Commit()
		}
	}()

	rt := sl.resTypes["User"]
	user, err := sl.getUsingTx(userId, rt, tx)
	if err != nil {
		return nil, err
	}

	keys := user.AuthData.Skeys
	if keys == nil {
		// debug a slightly different message than what is advertised
		log.Debugf("there are no securitykeys configured for the user %s", userId)
		msg := fmt.Sprintf("no securitykey exists with the credential ID %s", credentialId)
		return nil, base.NewNotFoundError(msg)
	} else if _, ok := keys[credentialId]; !ok {
		msg := fmt.Sprintf("no securitykey exists with the credential ID %s", credentialId)
		log.Debugf(msg)
		return nil, base.NewNotFoundError(msg)
	}

	delete(user.AuthData.Skeys, credentialId)
	user.UpdateLastModTime(sl.cg.NewCsn())
	sl.storeResource(tx, user)
	log.Debugf("deleted security key %s of user %s", credentialId, userId)
	return user, nil
}

func (sl *Silo) StoreSecurityKey(rid string, secKey *base.SecurityKey) (*base.Resource, error) {
	tx, err := sl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to begin transaction for storing securitykey %#v", err)
		return nil, err
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			log.Debugf("Error while storing security key %#v", err)
		} else {
			tx.Commit()
		}
	}()

	rt := sl.resTypes["User"]
	user, err := sl.getUsingTx(rid, rt, tx)
	if err != nil {
		return nil, err
	}

	if user.AuthData.Skeys == nil {
		user.AuthData.Skeys = make(map[string]*base.SecurityKey)
	}

	user.AuthData.Skeys[secKey.CredentialId] = secKey
	user.UpdateLastModTime(sl.cg.NewCsn())
	sl.storeResource(tx, user)

	return user, nil
}

func (sl *Silo) UpdateAuthData(rid string, version string, ad base.AuthData) error {
	tx, err := sl.db.Begin(true)
	if err != nil {
		log.Warningf("Failed to begin transaction for updating AuthData %#v", err)
		return err
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			log.Debugf("Error while updating AuthData key %#v", err)
		} else {
			tx.Commit()
		}
	}()

	rt := sl.resTypes["User"]
	user, err := sl.getUsingTx(rid, rt, tx)
	if err != nil {
		return err
	}

	curVersion := user.GetVersion()
	if strings.Compare(curVersion, version) > 0 {
		return fmt.Errorf("replication event is older than the current version %s of the target resource %s, aborting authdata update", curVersion, rid)
	}
	user.AuthData = &ad
	// update the version with the given value
	meta := user.GetMeta().GetFirstSubAt()
	meta["version"].Values[0] = version
	sl.storeResource(tx, user)

	return nil
}
