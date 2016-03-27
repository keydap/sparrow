package silo

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
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
	db        *bolt.DB                     // DB handle
	resources map[string][]byte            // the resource buckets
	indices   map[string]map[string]*Index // the index buckets, each index name will be in the form {resource-name}:{attribute-name}
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
	}

	return err
}

// Get the resource ID associated with the given attribute value
// This method is only applicable for unique attributes
func (idx *Index) GetRid(val string, tx *bolt.Tx) string {
	vData := idx.convert(val)
	ridBytes := tx.Bucket(idx.BnameBytes).Get(vData)

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

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(BUC_RESOURCES)
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(BUC_INDICES)
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

			isNewIndex, idx, err := sl.createIndexBucket(rc.Name, idxName, at)
			if err != nil {
				return nil, err
			}

			if isNewIndex {
				newIndices = append(newIndices, idx.Name)
			}
		}
	}

	// delete the unused resource or index buckets
	err = sl.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BUC_RESOURCES)
		bucket.ForEach(func(k, v []byte) error {
			resName := string(k)
			_, present := sl.indices[resName]
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
			if !present {
				log.Infof("Deleting unused bucket of index %s of resource %s", idxName, resName)
				bucket.Delete(k)
				tx.DeleteBucket(k)
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
	name := strings.ToLower(rc.Name)
	data := []byte(name)

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
		sl.resources[name] = data
		sl.indices[name] = make(map[string]*Index)
	}

	return err
}

func (sl *Silo) createIndexBucket(resourceName, attrName string, at *schema.AttrType) (bool, *Index, error) {
	bname := resourceName + RES_INDEX_DELIM + attrName
	bname = strings.ToLower(bname)
	bnameBytes := []byte(bname)

	idx := &Index{}
	idx.Name = strings.ToLower(attrName)
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
		resIdxMap := sl.indices[strings.ToLower(resourceName)]
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

func (sl *Silo) Insert(resource *provider.Resource) (res *provider.Resource, err error) {
	rid := utils.GenUUID()
	resource.SetId(rid)

	// validate the uniqueness constraints based on the schema
	rt := resource.GetType()
	rtName := strings.ToLower(rt.Name)

	//TODO remove all read-only attributes except ID

	// now, add meta attribute
	resource.AddMeta()

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
			res = resource
			log.Debugf("Successfully inserted resource with id %s", rid)
		}
	}()

	//log.Debugf("checking unique attributes %s", rt.UniqueAts)
	//log.Debugf("indices map %#v", sl.indices[rtName])
	for _, name := range rt.UniqueAts {
		// check if the value has already been used
		idx := sl.indices[rtName][name]
		attr := resource.GetAttr(name)
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

	for name, idx := range sl.indices[rtName] {
		attr := resource.GetAttr(name)
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
		}
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(resource)

	if err != nil {
		log.Warningf("Failed to encode resource %s", err)
		panic(err)
	}

	resBucket := tx.Bucket(sl.resources[rtName])
	err = resBucket.Put([]byte(rid), buf.Bytes())
	if err != nil {
		panic(err)
	}

	return resource, nil
}

func (sl *Silo) Get(rid string, rt *schema.ResourceType) (resource *provider.Resource, err error) {
	ridBytes := []byte(rid)
	rtNameBytes := sl.resources[strings.ToLower(rt.Name)]

	err = sl.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket(rtNameBytes)

		resData := buck.Get(ridBytes)
		if len(resData) > 0 {
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
	rtName := strings.ToLower(rt.Name)
	rtNameBytes := sl.resources[rtName]

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

	for name, idx := range sl.indices[rtName] {
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

	return nil
}

func (sl *Silo) Search() {

}
