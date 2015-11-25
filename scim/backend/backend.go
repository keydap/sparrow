package backend

import (
	"strings"
	//"encoding/json"
	"github.com/boltdb/bolt"
)

var (
	// a bucket that holds the names of the resource buckets e.g users, groups etc.
	BUC_RESOURCES = []byte("resources")

	// a bucket that holds the names of the resource buckets e.g users, groups etc.
	BUC_INDICES = []byte("indices")
)

type Backend struct {
	db        *bolt.DB          // DB handle
	resources map[string][]byte // the resource buckets
	indices   map[string]*Index // the index buckets, each index name will be in the form {resource-name}_{attribute-name}
}

type Index struct {
	name        string
	nameBytes   []byte
	allowDupKey bool
}

func Open(path string) (*Backend, error) {
	db, err := bolt.Open(path, 0644, nil)

	if err != nil {
		return nil, err
	}

	bc := &Backend{}
	bc.db = db
	bc.resources = make(map[string][]byte)
	bc.indices = make(map[string]*Index)

	err = db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(BUC_RESOURCES)
		if err != nil {
			return err
		}

		err = fillResourceMap(bucket, bc.resources)
		if err != nil {
			return err
		}

		bucket, err = tx.CreateBucketIfNotExists(BUC_INDICES)
		if err != nil {
			return err
		}

		err = fillIndexMap(bucket, bc.indices)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return bc, nil
}

func (bc *Backend) CreateResourceBucket(name string) error {
	name = strings.ToLower(name)
	data := []byte(name)
	err := bc.createBucket(data)

	if err == nil {
		bc.resources[name] = data
	}

	return err
}

func (bc *Backend) CreateIndexBucket(resourceName, attrName string, allowDupKey bool) error {
	name := resourceName + "_" + attrName
	name = strings.ToLower(name)
	data := []byte(name)

	err := bc.createBucket(data)

	if err == nil {
		idx := &Index{}
		idx.name = name
		idx.nameBytes = data
		idx.allowDupKey = allowDupKey
		bc.indices[name] = idx
	}

	return err
}

func (bc *Backend) createBucket(name []byte) error {
	err := bc.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(name)
		return err
	})

	return err
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

		idx := &Index{}
		idx.name = name
		idx.nameBytes = nameBytes

		if v[0] == 1 {
			idx.allowDupKey = true
		}

		m[name] = idx
		return nil
	})

	return err
}
