package silo

import (
	"fmt"
	"github.com/boltdb/bolt"
	"reflect"
	"sparrow/scim/base"
	"sparrow/scim/schema"
)

func (sl *Silo) Patch(rid string, pr *base.PatchReq, rt *schema.ResourceType) (res *base.Resource, err error) {
	res, err = sl.Get(rid, rt)

	if err != nil {
		return nil, err
	}

	tx, err := sl.db.Begin(true)

	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for modifying the resource [%s]", err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return nil, err
	}

	defer func() {
		e := recover()
		if e != nil {
			tx.Rollback()
			err = e.(error)
			res = nil
			log.Debugf("failed to modify %s resource [%s]", rt.Name, err)
		} else {
			tx.Commit()
			log.Debugf("Successfully modified resource with id %s", rid)
		}
	}()

	mh := &modifyHints{}

	for _, po := range pr.Operations {
		switch po.Op {
		case "add":
			sl.handleAdd(po, res, rid, mh, tx)
		}
	}

	if mh.modified {
		res.UpdateLastModTime()
		sl.storeResource(tx, res)
	}

	return res, nil
}

func (sl *Silo) handleAdd(po *base.PatchOp, res *base.Resource, rid string, mh *modifyHints, tx *bolt.Tx) {
	existsPath := (po.ParsedPath != nil)

	rt := res.GetType()
	prIdx := sl.getSysIndex(rt.Name, "presence")

	if !existsPath {
		var addRs *base.Resource
		var err error
		if obj, ok := po.Value.(map[string]interface{}); ok {
			addRs, err = base.ToResource(res.GetType(), sl.schemas, obj)
			if err != nil {
				panic(err)
			}
		} else {
			detail := fmt.Sprintf("Invalid value type given in the patch operation %#v", po.Value)
			log.Debugf(detail)
			panic(base.NewBadRequestError(detail))
		}

		for _, sa := range addRs.Core.SimpleAts {
			sl.addAttrTo(res, sa, tx, prIdx, mh)
		}

		for _, ca := range addRs.Core.ComplexAts {
			sl.addAttrTo(res, ca, tx, prIdx, mh)
		}

		for _, ext := range addRs.Ext {
			for _, sa := range ext.SimpleAts {
				sl.addAttrTo(res, sa, tx, prIdx, mh)
			}

			for _, ca := range ext.ComplexAts {
				sl.addAttrTo(res, ca, tx, prIdx, mh)
			}
		}

		// to avoid a lengthy else block below
		return
	}

	pp := po.ParsedPath

	if pp.AtType.IsComplex() {
		tAt := res.GetAttr(pp.AtType.NormName)
		if tAt == nil {
			// just add it
			ca := base.ParseComplexAttr(pp.AtType, po.Value)
			sl.addAttrTo(res, ca, tx, prIdx, mh)
		} else {
			tCa := tAt.GetComplexAt()
			if pp.AtType.MultiValued {
				// po.Value can be array of subAtMapS too right?
				rv := reflect.ValueOf(po.Value)
				kind := rv.Kind()
				arrLen := rv.Len()

				if (kind == reflect.Slice) || (kind == reflect.Array) {
					prmSet := false
					for i := 0; i < arrLen; i++ {
						val := rv.Index(i).Interface()
						subAtMap, p := base.ParseSubAtList(val, pp.AtType)
						if p {
							if !prmSet {
								prmSet = true
							} else {
								detail := fmt.Sprintf("More than one sub-attribute object has the primary flag set in the %d operation", po.Index)
								panic(base.NewBadRequestError(detail))
							}
						}

						if prmSet {
							// reset any other sub-list's primary flag if set
							tCa.UnsetPrimaryFlag()
						}

						tCa.SubAts = append(tCa.SubAts, subAtMap)
						sl.addSubAtMapToIndex(tCa.Name, subAtMap, prIdx, rt.Name, rid, tx)
					}
				} else {
					subAtMap, primary := base.ParseSubAtList(po.Value, pp.AtType)
					if primary {
						// reset any other sub-list's primary flag if set
						tCa.UnsetPrimaryFlag()
					}

					tCa.SubAts = append(tCa.SubAts, subAtMap)
					// index the subAtMap
					sl.addSubAtMapToIndex(tCa.Name, subAtMap, prIdx, rt.Name, rid, tx)
				}
			} else { // merge them
				subAtMap, _ := base.ParseSubAtList(po.Value, pp.AtType)
				mergeSubAtMap(tCa.SubAts[0], subAtMap, mh)
			}
		}
	} else { // handle SimpleAttributes
		if pp.ParentType != nil {
			var tSaMap map[string]*base.SimpleAttribute
			tCa := res.GetAttr(pp.ParentType.NormName).GetComplexAt()
			if pp.SlctrType != nil {
				matched := false
				for _, saMap := range tCa.SubAts {
					sa := saMap[pp.SlctrType.NormName]
					if sa != nil {
						matched = base.Compare(pp.SlctrType, sa.Values[0], pp.SlctrVal)
						if matched {
							tSaMap = saMap
							break
						}
					}
				}

				if !matched {
					detail := fmt.Sprintf("The selector %s present in the path of %d operation didn't match any attribute", po.Path, po.Index)
					se := base.NewBadRequestError(detail)
					panic(se)
				}
			}

			if tSaMap == nil {
				tSaMap = tCa.SubAts[0]
			}

			sa := base.ParseSimpleAttr(pp.AtType, convertSaValueBeforeParsing(pp.AtType, po.Value))

			if sa.Name == "primary" {
				if sa.Values[0].(bool) {
					tCa.UnsetPrimaryFlag()
				}
			}

			tSa := tSaMap[pp.AtType.NormName]

			atPath := pp.ParentType.NormName + "." + sa.Name

			if tSa == nil {
				tSaMap[pp.AtType.NormName] = sa
				sl.addSAtoIndex(sa, atPath, prIdx, rt.Name, rid, tx)
				mh.markDirty()
			} else if !sa.Equals(tSa) {
				//re-index
				sl.dropSAtFromIndex(tSa, atPath, prIdx, rt.Name, rid, tx)
				tSaMap[pp.AtType.NormName] = sa
				sl.addSAtoIndex(sa, atPath, prIdx, rt.Name, rid, tx)
				mh.markDirty()
			}

		} else {
			sa := base.ParseSimpleAttr(pp.AtType, convertSaValueBeforeParsing(pp.AtType, po.Value))
			tAt := res.GetAttr(pp.AtType.NormName)
			if tAt == nil {
				res.AddSimpleAt(sa)
				//index
				sl.addSAtoIndex(sa, sa.Name, prIdx, rt.Name, rid, tx)
				mh.markDirty()
			} else {
				tSa := tAt.GetSimpleAt()
				if !sa.Equals(tSa) {
					//re-index
					sl.dropSAtFromIndex(tSa, sa.Name, prIdx, rt.Name, rid, tx)
					tSa.Values = sa.Values
					sl.addSAtoIndex(sa, sa.Name, prIdx, rt.Name, rid, tx)
					mh.markDirty()
				}
			}
		}
	}
}

func (sl *Silo) addAttrTo(target *base.Resource, attr base.Attribute, tx *bolt.Tx, prIdx *Index, mh *modifyHints) {
	rt := target.GetType()
	rid := target.GetId()
	atType := attr.GetType()

	if atType.IsReadOnly() {
		detail := fmt.Sprintf("Cannot add read-only attribute %s to resource %s", atType.Name, target.GetId())
		log.Debugf(detail)
		se := base.NewBadRequestError(detail)
		panic(se)
	}

	//parentType := atType.Parent()

	var atg *base.AtGroup

	if atType.SchemaId == rt.Schema {
		atg = target.Core // core will never be nil
	} else {
		atg = target.Ext[atType.SchemaId]

		// add extension schema if not already present
		if atg == nil {
			atg = base.NewAtGroup()
		}
		target.Ext[atType.SchemaId] = atg
		target.UpdateSchemas()
	}

	if atType.IsComplex() {
		tCa := atg.ComplexAts[atType.NormName]
		ca := attr.GetComplexAt()
		if tCa == nil {
			// attr must be a complex AT, must add it
			atg.ComplexAts[atType.NormName] = ca
			sl.addCAtoIndex(ca, prIdx, rt.Name, rid, tx)
			mh.markDirty()
		} else {
			if atType.IsImmutable() {
				detail := fmt.Sprintf("Cannot add immutable attribute %s to resource %s, value already exists", atType.Name, target.GetId())
				log.Debugf(detail)
				se := base.NewBadRequestError(detail)
				se.ScimType = base.ST_MUTABILITY
				panic(se)
			}

			if atType.MultiValued {
				// reset any other sub-list's primary flag if set
				if ca.HasPrimarySet() {
					tCa.UnsetPrimaryFlag()
				}

				tCa.SubAts = append(tCa.SubAts, ca.SubAts...)
				for _, subAtMap := range ca.SubAts {
					sl.addSubAtMapToIndex(tCa.Name, subAtMap, prIdx, rt.Name, rid, tx)
				}
				mh.markDirty()
			} else {
				// merge complex attributes
				sl.dropCAtFromIndex(tCa, prIdx, rt.Name, rid, tx)
				tMap := tCa.SubAts[0]
				sMap := ca.SubAts[0]
				mergeSubAtMap(tMap, sMap, mh)
				sl.addCAtoIndex(tCa, prIdx, rt.Name, rid, tx)
			}
		}
	} else {
		sa := attr.GetSimpleAt()
		tAt := target.GetAttr(sa.Name)
		if tAt == nil {
			target.AddSimpleAt(sa)
			sl.addSAtoIndex(sa, sa.Name, prIdx, rt.Name, rid, tx)
			mh.markDirty()
		} else {
			tSa := tAt.GetSimpleAt()
			if !sa.Equals(tSa) {
				sl.dropSAtFromIndex(tSa, tSa.Name, prIdx, rt.Name, rid, tx)
				target.AddSimpleAt(sa)
				sl.addSAtoIndex(sa, sa.Name, prIdx, rt.Name, rid, tx)
				mh.markDirty()
			}
		}
	}
}

func (sl *Silo) dropSAtFromIndex(sa *base.SimpleAttribute, atPath string, prIdx *Index, resName string, rid string, tx *bolt.Tx) {
	for _, val := range sa.Values {
		idx := sl.getIndex(resName, atPath)
		if idx != nil {
			err := prIdx.remove(atPath, rid, tx)
			if err != nil {
				panic(err)
			}

			err = idx.remove(val, rid, tx)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (sl *Silo) dropCAtFromIndex(exAt *base.ComplexAttribute, prIdx *Index, resName string, rid string, tx *bolt.Tx) {
	// drop the old values from index
	for _, saMap := range exAt.SubAts {
		for _, sa := range saMap {
			atPath := exAt.Name + "." + sa.Name
			idx := sl.getIndex(resName, atPath)
			if idx != nil {
				err := prIdx.remove(atPath, rid, tx)
				if err != nil {
					panic(err)
				}

				// the SimpleAttributes here will always be single valued
				err = idx.remove(sa.Values[0], rid, tx)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func (sl *Silo) addSAtoIndex(sa *base.SimpleAttribute, atPath string, prIdx *Index, resName string, rid string, tx *bolt.Tx) {
	idx := sl.getIndex(resName, atPath)
	if idx == nil {
		return
	}

	atType := sa.GetType()
	// uniqueness is enforced only on single-valued SimpleAttributes
	if atType.IsUnique() {
		val := sa.Values[0]
		key := idx.convert(val)
		existing := idx.GetRid(key, tx)
		if (len(existing) > 0) && existing != rid {
			detail := fmt.Sprintf("Uniqueness violation, value %s of attribute %s already exists, cannot modify the resource", val, atType.Name)
			err := base.NewConflictError(detail)
			err.ScimType = base.ST_UNIQUENESS
			panic(err)
		}
	}

	for _, val := range sa.Values {
		err := prIdx.add(atPath, rid, tx)
		if err != nil {
			panic(err)
		}

		err = idx.add(val, rid, tx)
		if err != nil {
			panic(err)
		}
	}
}

func (sl *Silo) addCAtoIndex(ca *base.ComplexAttribute, prIdx *Index, resName string, rid string, tx *bolt.Tx) {
	for _, saMap := range ca.SubAts {
		sl.addSubAtMapToIndex(ca.Name, saMap, prIdx, resName, rid, tx)
	}
}

func (sl *Silo) addSubAtMapToIndex(parentName string, saMap map[string]*base.SimpleAttribute, prIdx *Index, resName string, rid string, tx *bolt.Tx) {
	for _, sa := range saMap {
		atPath := parentName + "." + sa.Name
		idx := sl.getIndex(resName, atPath)
		if idx != nil {
			err := prIdx.add(atPath, rid, tx)
			if err != nil {
				panic(err)
			}

			// the SimpleAttributes here will always be single valued
			err = idx.add(sa.Values[0], rid, tx)
			if err != nil {
				panic(err)
			}
		}
	}
}
func mergeSubAtMap(tMap, sMap map[string]*base.SimpleAttribute, mh *modifyHints) bool {
	merged := false

	for name, tSa := range tMap {
		if sa, ok := sMap[name]; ok {
			if !tSa.Equals(sa) {
				tMap[name] = sa
				mh.markDirty()
				merged = true
			}
			// delete from the source ca
			delete(sMap, name)
		}
	}

	for name, sa := range sMap {
		tMap[name] = sa
		mh.markDirty()
		merged = true
	}

	return merged
}

// places the given value in an array if the attribute is multivalued and
// given value is not an array
func convertSaValueBeforeParsing(atType *schema.AttrType, val interface{}) interface{} {
	if atType.MultiValued {
		rv := reflect.ValueOf(val)
		k := rv.Kind()
		if k != reflect.Slice && k != reflect.Array {
			arr := make([]interface{}, 1)
			arr[0] = val
			return arr
		}
	}

	return val
}
