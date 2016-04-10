package silo

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
	"math"
	"sparrow/scim/conf"
	"sparrow/scim/provider"
	"sparrow/scim/schema"
	"sparrow/scim/utils"
	"strconv"
	"strings"
)

var (
	// a bucket that holds the names of the resource buckets e.g users, groups etc.
	BUC_RESOURCES = []byte("resources")

	// a bucket that holds the names of the resource buckets e.g users, groups etc.
	BUC_INDICES = []byte("indices")

	// a bucket that holds the total number of each of the resources present and the the tuple count in each of their indices
	BUC_COUNTS = []byte("counts")

	// the delimiter that separates resource and index name
	RES_INDEX_DELIM = ":"
)

var log logger.Logger

var schemas map[string]*schema.Schema
var restypes map[string]*schema.ResourceType

func init() {
	log = logger.GetLogger("sparrow.scim.silo")
}

type Silo struct {
	db         *bolt.DB                     // DB handle
	resources  map[string][]byte            // the resource buckets
	indices    map[string]map[string]*Index // the index buckets, each index name will be in the form {resource-name}:{attribute-name}
	sysIndices map[string]map[string]*Index
	resCounts  map[string]int64
}

type Index struct {
	Bname         string // name of the bucket
	Name          string
	BnameBytes    []byte
	AllowDupKey   bool
	ValType       string // save the attribute's type name as a string
	CaseSensitive bool
	db            *bolt.DB
	count         int64 // the number of records present in this index (ecluding the count keys, if any)
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

/*func (idx *Index) readCount(tx *bolt.Tx) int64 {
	buck := tx.Bucket(BUC_COUNTS)
	cb := buck.Get(idx.BnameBytes)
	if cb == nil {
		idx.count = 0
	} else {
		idx.count = utils.Btoi(cb)
	}

	return idx.count
}*/

// Gets the number of values associated with the given key present in the index
func (idx *Index) keyCount(key string, tx *bolt.Tx) int64 {
	log.Debugf("getting count of value %s in the index %s", key, idx.Name)
	buck := tx.Bucket(idx.BnameBytes)
	var count int64
	count = 0

	if idx.AllowDupKey {
		countKey := []byte(strings.ToLower(key) + "_count")
		cb := buck.Get(countKey)
		if cb != nil {
			count = utils.Btoi(cb)
		}
	} else {
		vData := idx.convert(key)
		val := buck.Get(vData)
		if val != nil {
			count = 1
		}
	}

	return count
}

// Inserts the given <attribute value, resource ID> tuple in the index
func (idx *Index) add(val string, rid string, tx *bolt.Tx) error {
	log.Debugf("adding value %s of resource %s to index %s", val, rid, idx.Name)
	vData := idx.convert(val)
	buck := tx.Bucket(idx.BnameBytes)

	var err error
	if idx.AllowDupKey {
		dupBuck := buck.Bucket(vData)

		countKey := []byte(strings.ToLower(val) + "_count")
		var count int64
		firstCount := false

		if dupBuck == nil {
			dupBuck, err = buck.CreateBucket(vData)
			if err != nil {
				return err
			}

			err = buck.Put(countKey, utils.Itob(1))
			if err != nil {
				return err
			}
			firstCount = true
		} else {
			cb := buck.Get(countKey)
			count = utils.Btoi(cb)
		}

		err = dupBuck.Put([]byte(rid), []byte(nil))
		if err != nil {
			return err
		}

		if !firstCount {
			count++
			err = buck.Put(countKey, utils.Itob(count))
		}
	} else {
		err = buck.Put(vData, []byte(rid))
		if err != nil {
			return err
		}
	}

	// update count of index
	countsBuck := tx.Bucket(BUC_COUNTS)

	// TODO guard against multiple threads
	idx.count++
	err = countsBuck.Put(idx.BnameBytes, utils.Itob(idx.count))
	if err != nil {
		idx.count-- // restore if there is an error
		return err
	}

	return err
}

func (idx *Index) remove(val string, rid string, tx *bolt.Tx) error {
	log.Debugf("removing value %s of resource %s from index %s", val, rid, idx.Name)
	vData := idx.convert(val)
	buck := tx.Bucket(idx.BnameBytes)

	var err error
	if idx.AllowDupKey {
		dupBuck := buck.Bucket(vData)

		if dupBuck != nil {
			countKey := []byte(strings.ToLower(val) + "_count")

			cb := buck.Get(countKey)
			count := utils.Btoi(cb)

			if count > 1 {
				err = dupBuck.Delete([]byte(rid))
				if err != nil {
					return err
				}

				count--
				err = buck.Put(countKey, utils.Itob(count))
				if err != nil {
					return err
				}
			} else {
				err = buck.DeleteBucket(vData)
				log.Debugf("Deleting the bucket associated with %s %s", val, err)
				if err != nil {
					return err
				}

				log.Debugf("Deleting the bucket counter associated with %s", val)
				err = buck.Delete(countKey)
			}
		}
	} else {
		err = buck.Delete(vData)
		if err != nil {
			return err
		}
	}

	// update count of index
	countsBuck := tx.Bucket(BUC_COUNTS)

	idx.count--
	err = countsBuck.Put(idx.BnameBytes, utils.Itob(idx.count))
	if err != nil {
		idx.count++ // restore count if there is an error
		return err
	}

	return err
}

// Get the resource ID associated with the given attribute value
// This method is only applicable for unique attributes
func (idx *Index) GetRid(val string, tx *bolt.Tx) string {
	vData := idx.convert(val)
	buc := tx.Bucket(idx.BnameBytes)
	ridBytes := buc.Get(vData)

	if ridBytes != nil {
		rid := string(ridBytes)
		return rid
	}

	return ""
}

// Get the resource ID associated with the given attribute value
// This method is applicable for multivalued attributes only
func (idx *Index) GetRids(val string, tx *bolt.Tx) []string {
	vData := idx.convert(val)
	buck := tx.Bucket(idx.BnameBytes)

	dupBuck := buck.Bucket(vData)

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

func (idx *Index) HasVal(val string, tx *bolt.Tx) bool {
	return len(idx.GetRid(val, tx)) != 0
}

func (idx *Index) convert(val string) []byte {
	var vData []byte
	switch idx.ValType {
	case "string":
		if !idx.CaseSensitive {
			val = strings.ToLower(val)
		}
		vData = []byte(val)
	case "integer":
		i, _ := strconv.ParseInt(val, 10, 64)
		vData = utils.Itob(i)
	case "decimal":
		f, _ := strconv.ParseFloat(val, 64)
		vData = utils.Ftob(f)
	}

	return vData
}

func Open(path string, config *conf.Config, rtypes map[string]*schema.ResourceType, sm map[string]*schema.Schema) (*Silo, error) {
	restypes = rtypes
	schemas = sm

	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	sl := &Silo{}
	sl.db = db
	sl.resources = make(map[string][]byte)
	sl.indices = make(map[string]map[string]*Index)
	sl.sysIndices = make(map[string]map[string]*Index)
	sl.resCounts = make(map[string]int64)

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_RESOURCES)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_INDICES)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_COUNTS)
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

	for _, rc := range config.Resources {

		var rt *schema.ResourceType
		for _, v := range rtypes {
			if v.Name == rc.Name {
				rt = v
				break
			}
		}

		if rt == nil {
			return nil, fmt.Errorf("Unknown resource name %s found in config", rc.Name)
		}

		err = sl.createResourceBucket(rc)
		if err != nil {
			return nil, err
		}

		// the unique attributes should always be indexed
		// this helps in faster insertion time checks on uniqueness of attributes
		rc.IndexFields = append(rc.IndexFields, rt.UniqueAts...)

		for _, idxName := range rc.IndexFields {
			at := rt.GetAtType(idxName)
			if at == nil {
				log.Warningf("There is no attribute with the name %s, index is not created", idxName)
				continue
			}

			resIdxMap := sl.indices[rc.Name]
			isNewIndex, idx, err := sl.createIndexBucket(rc.Name, idxName, at, false, resIdxMap)
			if err != nil {
				return nil, err
			}

			if isNewIndex {
				newIndices = append(newIndices, idx.Name)
			}
		}

		// create presence system index
		sysIdxMap := sl.sysIndices[rc.Name]

		prAt := &schema.AttrType{Description: "Virtual attribute type for presence index"}
		prAt.CaseExact = false
		prAt.MultiValued = true
		prAt.Type = "string"

		_, _, err := sl.createIndexBucket(rc.Name, "presence", prAt, true, sysIdxMap)
		if err != nil {
			return nil, err
		}
	}

	// delete the unused resource or index buckets and initialize the counts of the indices and resources
	err = sl.db.Update(func(tx *bolt.Tx) error {
		countBucket := tx.Bucket(BUC_COUNTS)

		bucket := tx.Bucket(BUC_RESOURCES)
		bucket.ForEach(func(k, v []byte) error {
			resName := string(k)
			resBucKey, present := sl.resources[resName]
			if !present {
				log.Infof("Deleting unused bucket of resource %s", resName)
				bucket.Delete(k)
				tx.DeleteBucket(k)
			} else {
				cb := countBucket.Get(resBucKey)
				if cb != nil {
					count := utils.Btoi(cb)
					sl.resCounts[resName] = count
					log.Infof("There are total %d %s resources during startup", count, resName)
				}
			}
			return nil
		})

		bucket = tx.Bucket(BUC_INDICES)
		bucket.ForEach(func(k, v []byte) error {
			idxBName := string(k)
			tokens := strings.Split(idxBName, RES_INDEX_DELIM)
			resName := tokens[0]
			idxName := tokens[1]
			idx, present := sl.indices[resName][idxName]
			if !present && !strings.HasSuffix(idxName, "_system") { // do not delete system indices
				log.Infof("Deleting unused bucket of index %s of resource %s", idxName, resName)
				bucket.Delete(k)
				tx.DeleteBucket(k)
			} else {
				cb := countBucket.Get(k)
				if cb != nil {
					idx.count = utils.Btoi(cb)
					log.Infof("Index %s has %d tuples during startup", idx.Name, idx.count)
				}
			}

			return nil
		})

		return err
	})

	return sl, nil
}

func (sl *Silo) Close() {
	log.Infof("Closing silo")
	sl.db.Close()
}

func (sl *Silo) createResourceBucket(rc conf.ResourceConf) error {
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
	if at.Parent != nil {
		idx.AllowDupKey = at.Parent.MultiValued
	} else {
		idx.AllowDupKey = at.MultiValued
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

func (sl *Silo) Insert(inRes *provider.Resource) (res *provider.Resource, err error) {
	inRes.RemoveReadOnlyAt()

	rid := utils.GenUUID()
	inRes.SetId(rid)

	// validate the uniqueness constraints based on the schema
	rt := inRes.GetType()

	// now, add meta attribute
	inRes.AddMeta()

	tx, err := sl.db.Begin(true)

	if err != nil {
		log.Criticalf("Could not begin a transaction for inserting the resource %s", err.Error())
		return nil, err
	}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			tx.Rollback()
			res = nil
			log.Debugf("failed to insert resource %s", err)
		} else {
			tx.Commit()
			res = inRes
			log.Debugf("Successfully inserted resource with id %s", rid)
		}
	}()

	//log.Debugf("checking unique attributes %s", rt.UniqueAts)
	//log.Debugf("indices map %#v", sl.indices[rtName])
	for _, name := range rt.UniqueAts {
		// check if the value has already been used
		idx := sl.indices[rt.Name][name]
		attr := inRes.GetAttr(name)
		if attr.IsSimple() {
			sa := attr.GetSimpleAt()
			for _, val := range sa.Values {
				fmt.Printf("checking unique attribute %#v\n", idx)
				if idx.HasVal(val, tx) {
					err := fmt.Errorf("Uniqueness violation, value %s of attribute %s already exists", val, sa.Name)
					panic(err)
				}
			}
		}
	}

	prIdx := sl.getSysIndex(rt.Name, "presence")

	for name, idx := range sl.indices[rt.Name] {
		attr := inRes.GetAttr(name)
		if attr == nil {
			continue
		}
		if attr.IsSimple() {
			sa := attr.GetSimpleAt()
			for _, val := range sa.Values {
				err := idx.add(val, rid, tx)
				if err != nil {
					panic(err)
				}
			}

			err := prIdx.add(name, rid, tx) // do not add sa.Name that will lose the attribute path
			if err != nil {
				fmt.Println("error while adding into pr index ", err)
				panic(err)
			}
		}
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(inRes)

	if err != nil {
		log.Warningf("Failed to encode resource %s", err)
		panic(err)
	}

	resBucket := tx.Bucket(sl.resources[rt.Name])
	err = resBucket.Put([]byte(rid), buf.Bytes())
	if err != nil {
		panic(err)
	}

	// update count of index
	countsBuck := tx.Bucket(BUC_COUNTS)

	count := sl.resCounts[rt.Name]
	count++
	err = countsBuck.Put(sl.resources[rt.Name], utils.Itob(count))
	if err != nil {
		count-- // restore if there is an error
		return nil, err
	}

	sl.resCounts[rt.Name] = count

	return inRes, nil
}

func (sl *Silo) Get(rid string, rt *schema.ResourceType) (resource *provider.Resource, err error) {
	ridBytes := []byte(rid)
	rtNameBytes := sl.resources[rt.Name]

	err = sl.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket(rtNameBytes)

		resData := buck.Get(ridBytes)
		if resData != nil {
			reader := bytes.NewReader(resData)
			decoder := gob.NewDecoder(reader)
			err = decoder.Decode(&resource)
		}

		return err
	})

	if err != nil {
		return nil, err
	}

	if resource != nil {
		resource.SetSchema(rt)
	}

	return resource, nil
}

func (sl *Silo) Remove(rid string, rt *schema.ResourceType) (err error) {
	ridBytes := []byte(rid)
	rtNameBytes := sl.resources[rt.Name]

	tx, err := sl.db.Begin(true)
	if err != nil {
		return err
	}

	defer func() {
		err := recover()
		if err != nil {
			log.Debugf("failed to remove resource with ID %s\n %s", rid, err)
			tx.Rollback()
		} else {
			tx.Commit()
			log.Debugf("Successfully removed resource with ID %s", rid)
		}
	}()

	buck := tx.Bucket(rtNameBytes)
	resData := buck.Get(ridBytes)
	if len(resData) == 0 {
		return provider.NewNotFoundError(rt.Name + " resource with ID " + rid + " not found")
	}

	var resource *provider.Resource

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

	err = buck.Delete(ridBytes)

	if err != nil {
		return err
	}

	// update count of index
	countsBuck := tx.Bucket(BUC_COUNTS)

	count := sl.resCounts[rt.Name]
	count--
	err = countsBuck.Put(sl.resources[rt.Name], utils.Itob(count))
	if err != nil {
		count++ // restore if there is an error
		return err
	}

	sl.resCounts[rt.Name] = count

	return nil
}

func (sl *Silo) Search(sc *provider.SearchContext) (results map[string]*provider.Resource, err error) {
	tx, err := sl.db.Begin(false)

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			log.Debugf("Error while searching for resources %s", err.Error())
			results = nil
		}

		tx.Rollback()
	}()

	if err != nil {
		panic(err)
	}

	candidates := make(map[string]*provider.Resource)

	results = make(map[string]*provider.Resource)

	for _, rsType := range sc.ResTypes {
		count := getOptimizedResults(sc.Filter, rsType, tx, sl, candidates)
		evaluator := buildEvaluator(sc.Filter)

		buc := tx.Bucket(sl.resources[rsType.Name])

		if count < math.MaxInt64 {
			for k, _ := range candidates {
				data := buc.Get([]byte(k))
				reader := bytes.NewReader(data)
				decoder := gob.NewDecoder(reader)

				if data != nil {
					var rs *provider.Resource
					err = decoder.Decode(&rs)
					if err != nil {
						panic(err)
					}

					rs.SetSchema(rsType)
					if evaluator.evaluate(rs) {
						results[k] = rs
					}
				}
			}
		}
	}

	return results, nil
}
