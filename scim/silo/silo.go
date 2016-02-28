package silo

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/boltdb/bolt"
	logger "github.com/juju/loggo"
	"reflect"
	"sparrow/scim/conf"
	"sparrow/scim/provider"
	"sparrow/scim/schema"
	"sparrow/scim/utils"
	"strconv"
	"strings"
	"math"
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

func init() {
	log = logger.GetLogger("sparrow.scim.silo")
}

type Backend struct {
	db        *bolt.DB                     // DB handle
	resources map[string]map[string]*Index // the resource buckets and the index buckets, each index name will be in the form {resource-name}:{attribute-name}
}

type Index struct {
	Bname         string // name of the bucket
	Name          string
	BnameBytes    []byte
	AllowDupKey   bool
	ValType       string // instead save the attribute's type name as a string
	CaseSensitive bool
	db            *bolt.DB
}

func (idx *Index) add(val string) bool {
	var vData []byte
	switch idx.ValType {
	case "string":
		if !idx.CaseSensitive {
			val = strings.ToLower(val)
		}
		vData = []byte(string)
	case "integer":
		vData = utils.Itob(strconv.Atoi(val, 10, 64))
	case "decimal":
		vData = utils.Ftob(strconv.ParseFloat(val, 64))
	}
	
	math.Float64bits()
	return true
}

//func (idx *Index) hasValue(val string) bool {
//	switch idx.ValType {
//	case "string":
//	}
//	return true
//}

func Open(config *conf.Config, rtypes map[string]*schema.ResourceType, path string) (*Backend, error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	bc := &Backend{}
	bc.db = db
	bc.resources = make(map[string]map[string]*Index)

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

	newIndices := make([]string, 5)

	for _, rc := range config.Resources {
		rt := rtypes[rc.Name]
		if rt == nil {
			return nil, fmt.Errorf("Unknown resource name %s found in config", rc.Name)
		}

		err = bc.CreateResourceBucket(rc)
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

			isNewIndex, idx, err := bc.CreateIndexBucket(rc.Name, idxName, at)
			if err != nil {
				return nil, err
			}

			if isNewIndex {
				newIndices = append(newIndices, idx.name)
			}
		}
	}

	// delete the unused resource or index buckets
	err = bc.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BUC_RESOURCES)
		bucket.ForEach(func(k, v []byte) error {
			resName := string(k)
			_, present := bc.resources[resName]
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
			_, present := bc.resources[resName][idxName]
			if !present {
				log.Infof("Deleting unused bucket of index %s of resource %s", idxName, resName)
				bucket.Delete(k)
				tx.DeleteBucket(k)
			}
			return nil
		})

		return err
	})

	return bc, nil
}

func (bc *Backend) CreateResourceBucket(rc conf.ResourceConf) error {
	name := strings.ToLower(rc.Name)
	data := []byte(name)

	err := bc.db.Update(func(tx *bolt.Tx) error {
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
		bc.resources[name] = make(map[string]*Index)
	}

	return err
}

func (bc *Backend) CreateIndexBucket(resourceName, attrName string, at *schema.AttrType) (bool, *Index, error) {
	bname := resourceName + RES_INDEX_DELIM + attrName
	bname = strings.ToLower(bname)
	bnameBytes := []byte(bname)

	idx := &Index{}
	idx.Name = strings.ToLower(attrName)
	idx.Bname = bname
	idx.BnameBytes = bnameBytes
	idx.CaseSensitive = at.CaseExact
	idx.ValType = at.Type
	idx.AllowDupKey = at.MultiValued
	idx.db = bc.db

	var isNewIndex bool

	err := bc.db.Update(func(tx *bolt.Tx) error {
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
		bc.resources[resourceName][idx.name] = idx
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

func (bc *Backend) insert(resource *provider.Resource) (*provider.Resource, error) {
	id := utils.GenUUID()
	resource.SetId(id)

	// validate the uniqueness contraints based on the schema
	rt := resource.GetType()

	for _, name := range rt.UniqueAts {
		// check if the value has been used already
		//		idx := bc.
		attr := resource.GetAttr(name)
		if attr.IsSimple() {
			sa := attr.GetSimpleAt()
			for _, val := range sa.Values {
				fmt.Print(val)
			}
		}
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(resource)
	
	gob.NewDecoder()

	if err != nil {
		log.Warningf("Failed to encode resource %s", err.Error())
		return resource, err
	}

	return nil, nil
}
