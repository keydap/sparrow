// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package silo

import (
	"fmt"
	"github.com/coreos/bbolt"
	"reflect"
	"runtime/debug"
	"sparrow/base"
	"sparrow/schema"
	"strings"
)

func (sl *Silo) Patch(rid string, pr *base.PatchReq, rt *schema.ResourceType) (res *base.Resource, err error) {
	tx, err := sl.db.Begin(true)

	if err != nil {
		detail := fmt.Sprintf("Could not begin a transaction for modifying the resource [%s]", err.Error())
		log.Criticalf(detail)
		err = base.NewInternalserverError(detail)
		return nil, err
	}

	sl.mutex.Lock()

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
		}

		if err != nil {
			tx.Rollback()
			res = nil
			if log.IsDebugEnabled() {
				log.Debugf("failed to modify %s resource [%s]", rt.Name, err)
				debug.PrintStack()
			}
		} else {
			tx.Commit()

			if rt.Name == "Group" {
				sl.Engine.UpsertRole(res, sl.resTypes)
			}

			log.Debugf("Successfully modified resource with id %s", rid)
		}

		sl.mutex.Unlock()
	}()

	res, err = sl.getUsingTx(rid, rt, tx)

	if err != nil {
		return nil, err
	}

	if strings.Compare(res.GetVersion(), pr.IfMatch) != 0 {
		msg := fmt.Sprintf("The given version %s of the resource to be patched %s doesn't match with stored version", pr.IfMatch, rid)
		log.Debugf(msg)
		return nil, base.NewPreCondError(msg)
	}

	mh := &modifyHints{}

	for _, po := range pr.Operations {
		log.Debugf("Patch %s operation on resource %s", po.Op, rid)
		switch po.Op {
		case "add":
			sl.handleAdd(po, res, rid, mh, tx)

		case "remove":
			sl.handleRemove(po, res, rid, mh, tx)

		case "replace":
			sl.handleReplace(po, res, rid, mh, tx)
		}
	}

	if mh.modified {
		res.UpdateLastModTime(sl.cg.NewCsn())
		sl.storeResource(tx, res)
	}

	return res, nil
}

func (sl *Silo) handleReplace(po *base.PatchOp, res *base.Resource, rid string, mh *modifyHints, tx *bolt.Tx) {
	rt := res.GetType()
	prIdx := sl.getSysIndex(rt.Name, "presence")

	pp := po.ParsedPath

	isGroup := (rt.Name == "Group")

	var displayName string
	if isGroup {
		displayName = res.GetAttr("displayname").GetSimpleAt().GetStringVal()
	}

	if pp == nil { // no path is provided
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
			sl.replaceAttrIn(res, sa, tx, prIdx, mh)
		}

		for _, ca := range addRs.Core.ComplexAts {
			if isGroup {
				if ca.Name == "members" {
					tCa := res.GetAttr("members")
					if tCa != nil {
						sl.deleteGroupMembers(tCa.GetComplexAt(), rid, tx)
					}
				}
			}

			sl.replaceAttrIn(res, ca, tx, prIdx, mh)

			if isGroup {
				if ca.Name == "members" {
					sl.addGroupMembers(ca, rid, displayName, tx)
				}
			}
		}

		for _, ext := range addRs.Ext {
			for _, sa := range ext.SimpleAts {
				sl.replaceAttrIn(res, sa, tx, prIdx, mh)
			}

			for _, ca := range ext.ComplexAts {
				sl.replaceAttrIn(res, ca, tx, prIdx, mh)
			}
		}

		// to avoid a lengthy else block below
		return
	}

	if pp.AtType.IsComplex() {
		isMembers := (isGroup && pp.AtType.NormName == "members")
		tAt := res.GetAttr(pp.AtType.NormName)
		if tAt == nil {
			// just add it
			ca := base.ParseComplexAttr(pp.AtType, po.Value)
			sl.addAttrTo(res, ca, tx, prIdx, mh)
			if isMembers {
				sl.addGroupMembers(ca, rid, displayName, tx)
			}
		} else {
			tCa := tAt.GetComplexAt()

			if pp.AtType.MultiValued {
				rv := reflect.ValueOf(po.Value)
				kind := rv.Kind()
				arrLen := rv.Len()

				ca := base.NewComplexAt(tCa.GetType())
				if (kind == reflect.Slice) || (kind == reflect.Array) {
					if pp.Slctr != nil {
						detail := fmt.Sprintf("Cannot replace multi-valued attribute %s of resource %s when selector is present but an array of values is given", pp.AtType.Name, rid)
						se := base.NewBadRequestError(detail)
						panic(se)
					}
					prmSet := false
					for i := 0; i < arrLen; i++ {
						val := rv.Index(i).Interface()
						subAtMap, p := base.ParseSubAtList(val, pp.AtType)
						if p {
							if !prmSet {
								prmSet = true
								// reset any other sub-list's primary flag if set
								tCa.UnsetPrimaryFlag()
							} else {
								detail := fmt.Sprintf("More than one sub-attribute object has the primary flag set in the %d operation", po.Index)
								panic(base.NewBadRequestError(detail))
							}
						}

						// the ca should hold only one subAtMap so keeping the key as a constant
						ca.SubAts[base.RandStr()] = subAtMap
					}

					sl.dropCAtFromIndex(tCa, prIdx, rt.Name, rid, tx)

					if isMembers {
						sl.deleteGroupMembers(tCa, rid, tx)
						sl.addGroupMembers(ca, rid, displayName, tx)
					}

					tCa.SubAts = ca.SubAts
					sl.addCAtoIndex(tCa, prIdx, rt.Name, rid, tx)
				} else {
					subAtMap, primary := base.ParseSubAtList(po.Value, pp.AtType)
					if primary {
						detail := fmt.Sprintf("Cannot set primary flag on multiple sub-attributes of attribute %s of resource %s", pp.AtType.Name, rid)
						se := base.NewBadRequestError(detail)
						panic(se)
					}

					if isMembers {
						sl.deleteGroupMembers(tCa, rid, tx)
					}

					sl.dropCAtFromIndex(tCa, prIdx, rt.Name, rid, tx)
					if pp.Slctr != nil {
						offsets := findSelectedObj(po, tCa)
						for _, o := range offsets {
							tSaMap := tCa.SubAts[o]
							for name, sa := range subAtMap {
								tSaMap[name] = sa
							}
						}
					} else { // replace all the subAts when no selector is specified
						tCa.SubAts = make(map[string]map[string]*base.SimpleAttribute)

					}
					sl.addCAtoIndex(tCa, prIdx, rt.Name, rid, tx)
					if isMembers {
						sl.addGroupMembers(tCa, rid, displayName, tx)
					}
					mh.markDirty()
				}
			} else { // merge them
				subAtMap, _ := base.ParseSubAtList(po.Value, pp.AtType)
				sl.dropCAtFromIndex(tCa, prIdx, rt.Name, rid, tx)
				mergeSubAtMap(tCa.GetFirstSubAt(), subAtMap, mh)
				sl.addCAtoIndex(tCa, prIdx, rt.Name, rid, tx)
			}
		}
	} else { // handle SimpleAttributes
		if pp.ParentType != nil {
			// handle members.value
			isMemberVal := (isGroup && pp.ParentType.NormName == "members" && pp.AtType.NormName == "value")
			var offsets []string
			tCa := res.GetAttr(pp.ParentType.NormName).GetComplexAt()
			if pp.Slctr != nil {
				offsets = findSelectedObj(po, tCa)
			} else {
				count := len(tCa.SubAts)
				if count > 1 && pp.ParentType.MultiValued { // multivalued attribute
					offsets = make([]string, count)
					i := 0
					for k, _ := range tCa.SubAts {
						offsets[i] = k
						i++
					}
				} else {
					_, k := tCa.GetFirstSubAtAndKey()
					offsets = []string{k}
				}
			}

			sa := base.ParseSimpleAttr(pp.AtType, convertSaValueBeforeParsing(pp.AtType, po.Value))

			if sa.Name == "primary" {
				if sa.Values[0].(bool) {
					tCa.UnsetPrimaryFlag()
				}
			}

			for _, o := range offsets {
				tSaMap := tCa.SubAts[o]
				tSa := tSaMap[pp.AtType.NormName]

				atPath := pp.ParentType.NormName + "." + sa.Name

				if tSa == nil {
					tSaMap[pp.AtType.NormName] = sa
					if isMemberVal {
						membersCa := base.NewComplexAt(tCa.GetType())
						membersCa.SubAts["1"] = tSaMap
						sl.addGroupMembers(membersCa, rid, displayName, tx)
					}
					sl.addSAtoIndex(sa, atPath, prIdx, rt.Name, rid, tx)
					mh.markDirty()
				} else if !sa.Equals(tSa) {
					//re-index
					if isMemberVal {
						sl._deleteGroupMembers(tSaMap, rid, tx)
					}

					sl.dropSAtFromIndex(tSa, atPath, prIdx, rt.Name, rid, tx)

					tSaMap[pp.AtType.NormName] = sa

					if isMemberVal {
						membersCa := base.NewComplexAt(tCa.GetType())
						membersCa.SubAts["1"] = tSaMap
						sl.addGroupMembers(membersCa, rid, displayName, tx)
					}

					sl.addSAtoIndex(sa, atPath, prIdx, rt.Name, rid, tx)
					mh.markDirty()
				}
			}

		} else {
			// this is unreachable for updates on Group's "members.value", hence no handling is needed here
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

func (sl *Silo) handleRemove(po *base.PatchOp, res *base.Resource, rid string, mh *modifyHints, tx *bolt.Tx) {
	rt := res.GetType()
	prIdx := sl.getSysIndex(rt.Name, "presence")

	pp := po.ParsedPath

	if pp.AtType.IsReadOnly() || pp.AtType.IsImmutable() || pp.AtType.Required {
		mutability := pp.AtType.Mutability
		if pp.AtType.Required {
			mutability = "required"
		}

		detail := fmt.Sprintf("Cannot remove %s attribute %s from resource %s", mutability, pp.AtType.Name, rid)
		log.Debugf(detail)
		se := base.NewBadRequestError(detail)
		se.ScimType = base.ST_MUTABILITY
		panic(se)
	}

	isGroup := (rt.Name == "Group")

	if pp.ParentType != nil {
		ca := res.GetAttr(pp.ParentType.Name).GetComplexAt()
		isMemberVal := (isGroup && pp.ParentType.NormName == "members" && pp.AtType.NormName == "value")

		if pp.Slctr != nil {
			offsets := findSelectedObj(po, ca)
			for _, key := range offsets {
				tSaMap := ca.SubAts[key]
				if isMemberVal {
					sl._deleteGroupMembers(tSaMap, rid, tx)
				}
				deleteAtFromSubAtMap(sl, pp, tSaMap, key, ca, prIdx, res, rid, tx, mh)
			}
		} else {
			if pp.ParentType.MultiValued {
				// delete the sub-attribute from all values
				for i, subAtMap := range ca.SubAts {
					if sa, ok := subAtMap[pp.AtType.NormName]; ok {
						if isMemberVal {
							sl._deleteGroupMembers(subAtMap, rid, tx)
						}
						delete(subAtMap, sa.Name)
						sl.dropSAtFromIndex(sa, ca.Name+"."+sa.Name, prIdx, rt.Name, rid, tx)
						if len(subAtMap) == 0 {
							delete(ca.SubAts, i)
						}

						mh.markDirty()
					}
				}
			} else {
				tSaMap, key := ca.GetFirstSubAtAndKey()
				deleteAtFromSubAtMap(sl, pp, tSaMap, key, ca, prIdx, res, rid, tx, mh)
			}
		}

	} else {
		isMembers := (isGroup && pp.AtType.NormName == "members")
		if pp.Slctr != nil {
			at := res.GetAttr(pp.AtType.NormName)
			if at.IsSimple() {
				detail := fmt.Sprintf("The attribute %s associated with the selector %s present in the path of operation %d is not a complex attribute", pp.AtType.Name, pp.Text, po.Index)
				se := base.NewBadRequestError(detail)
				panic(se)
			}
			ca := at.GetComplexAt()
			offsets := findSelectedObj(po, ca)
			for _, pos := range offsets {
				saMap := ca.SubAts[pos]
				if isMembers {
					sl._deleteGroupMembers(saMap, rid, tx)
				}
				sl.dropSubAtMapFromIndex(ca.Name, saMap, prIdx, rt.Name, rid, tx)
				delete(ca.SubAts, pos)
			}

			if len(ca.SubAts) == 0 {
				res.DeleteAttr(ca.Name)
			}
			mh.markDirty()
		} else {
			at := res.DeleteAttr(pp.AtType.NormName)
			if at != nil {
				if at.IsSimple() {
					sa := at.GetSimpleAt()
					sl.dropSAtFromIndex(sa, sa.Name, prIdx, rt.Name, rid, tx)
				} else {
					ca := at.GetComplexAt()
					if isMembers {
						sl.deleteGroupMembers(ca, rid, tx)
					}
					// removed CA
					sl.dropCAtFromIndex(ca, prIdx, rt.Name, rid, tx)
				}
				mh.markDirty()
			}
		}
	}
}

func (sl *Silo) handleAdd(po *base.PatchOp, res *base.Resource, rid string, mh *modifyHints, tx *bolt.Tx) {
	pp := po.ParsedPath

	rt := res.GetType()
	prIdx := sl.getSysIndex(rt.Name, "presence")

	isGroup := (res.GetType().Name == "Group")

	var displayName string
	if isGroup {
		displayName = res.GetAttr("displayname").GetSimpleAt().GetStringVal()
	}

	if pp == nil {
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
			if isGroup {
				if ca.Name == "members" {
					sl.addGroupMembers(ca, rid, displayName, tx)
				}
			}
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

	if pp.AtType.IsComplex() {
		isMembers := (isGroup && pp.AtType.NormName == "members")
		tAt := res.GetAttr(pp.AtType.NormName)
		if tAt == nil {
			// just add it
			ca := base.ParseComplexAttr(pp.AtType, po.Value)
			sl.addAttrTo(res, ca, tx, prIdx, mh)
			if isMembers {
				sl.addGroupMembers(ca, rid, displayName, tx)
			}
		} else {
			tCa := tAt.GetComplexAt()
			if pp.AtType.MultiValued {
				// po.Value can be array of subAtMapS too right?
				rv := reflect.ValueOf(po.Value)
				kind := rv.Kind()
				arrLen := rv.Len()

				ca := base.NewComplexAt(tCa.GetType())
				if (kind == reflect.Slice) || (kind == reflect.Array) {
					prmSet := false
					for i := 0; i < arrLen; i++ {
						val := rv.Index(i).Interface()
						subAtMap, p := base.ParseSubAtList(val, pp.AtType)
						// to handle cases like { "op": "add", "path": "emails", "value": [ {} ] }
						if len(subAtMap) == 0 {
							continue
						}

						if p {
							if !prmSet {
								prmSet = true
								// reset any other sub-list's primary flag if set
								tCa.UnsetPrimaryFlag()
								mh.markDirty()
							} else {
								detail := fmt.Sprintf("More than one sub-attribute object has the primary flag set in the %d operation", po.Index)
								panic(base.NewBadRequestError(detail))
							}
						}

						if isMembers {
							// the ca should hold only one subAtMap so keeping the key as a constant
							ca.SubAts["1"] = subAtMap
							sl.addGroupMembers(ca, rid, displayName, tx)
							// the $ref and type values will be updated in the subAtMap when addGroupMembers is called
							// so use this updated subAtMap
							tCa.SubAts[base.RandStr()] = subAtMap
						} else {
							tCa.SubAts[base.RandStr()] = subAtMap
						}

						sl.addSubAtMapToIndex(tCa.Name, subAtMap, prIdx, rt.Name, rid, tx)
						mh.markDirty()
					}
				} else {
					subAtMap, primary := base.ParseSubAtList(po.Value, pp.AtType)
					if primary {
						// reset any other sub-list's primary flag if set
						tCa.UnsetPrimaryFlag()
					}

					if isMembers {
						// the ca should hold only one subAtMap so keeping the key as a constant
						ca.SubAts["1"] = subAtMap
						sl.addGroupMembers(ca, rid, displayName, tx)
						// the $ref and type values will be updated in the subAtMap when addGroupMembers is called
						// so use this updated subAtMap
						tCa.SubAts[base.RandStr()] = subAtMap
					} else {
						tCa.SubAts[base.RandStr()] = subAtMap
					}

					// index the subAtMap
					sl.addSubAtMapToIndex(tCa.Name, subAtMap, prIdx, rt.Name, rid, tx)
					mh.markDirty()
				}
			} else { // merge them
				subAtMap, _ := base.ParseSubAtList(po.Value, pp.AtType)
				sl.dropCAtFromIndex(tCa, prIdx, rt.Name, rid, tx)
				mergeSubAtMap(tCa.GetFirstSubAt(), subAtMap, mh)
				sl.addCAtoIndex(tCa, prIdx, rt.Name, rid, tx)
			}
		}
	} else { // handle SimpleAttributes
		if pp.ParentType != nil {
			var offsets []string
			var tCa *base.ComplexAttribute

			tAt := res.GetAttr(pp.ParentType.NormName)

			// to handle cases where parent is not present but
			// a sub-attribute is being added using PATCH
			if tAt == nil {
				tCa = base.NewComplexAt(pp.ParentType)
				res.AddComplexAt(tCa)
			} else {
				tCa = tAt.GetComplexAt()
			}

			if pp.Slctr != nil {
				offsets = findSelectedObj(po, tCa)
			} else {
				_, key := tCa.GetFirstSubAtAndKey()
				// only initialize if the key is not empty
				if key != "" {
					offsets = []string{key}
				}
			}

			sa := base.ParseSimpleAttr(pp.AtType, convertSaValueBeforeParsing(pp.AtType, po.Value))
			if sa.GetType().IsImmutable() {
				detail := fmt.Sprintf("Cannot update immutable attribute %s", sa.Name)
				panic(base.NewBadRequestError(detail))
			}

			if sa.Name == "primary" {
				if sa.Values[0].(bool) {
					tCa.UnsetPrimaryFlag()
				}
			}

			atPath := pp.ParentType.NormName + "." + sa.Name

			// a new CA was just added above
			if offsets == nil {
				atMap := make(map[string]*base.SimpleAttribute)
				key := base.RandStr()
				tCa.SubAts[key] = atMap

				atMap[pp.AtType.NormName] = sa
				sl.addSAtoIndex(sa, atPath, prIdx, rt.Name, rid, tx)
				mh.markDirty()
			} else {
				for _, o := range offsets {
					tSaMap := tCa.SubAts[o]
					tSa := tSaMap[pp.AtType.NormName]

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
				}
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

				for _, subAtMap := range ca.SubAts {
					// the old key might have been regenerated so do not use the key
					// from the above loop, instead generate a new random key
					tCa.SubAts[base.RandStr()] = subAtMap
					sl.addSubAtMapToIndex(tCa.Name, subAtMap, prIdx, rt.Name, rid, tx)
				}
				mh.markDirty()
			} else {
				// merge complex attributes
				sl.dropCAtFromIndex(tCa, prIdx, rt.Name, rid, tx)
				tMap := tCa.GetFirstSubAt()
				sMap := ca.GetFirstSubAt()
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

func (sl *Silo) dropCAtFromIndex(ca *base.ComplexAttribute, prIdx *Index, resName string, rid string, tx *bolt.Tx) {
	// drop the old values from index
	for _, saMap := range ca.SubAts {
		sl.dropSubAtMapFromIndex(ca.Name, saMap, prIdx, resName, rid, tx)
	}
}

func (sl *Silo) dropSubAtMapFromIndex(parentName string, saMap map[string]*base.SimpleAttribute, prIdx *Index, resName string, rid string, tx *bolt.Tx) {
	for _, sa := range saMap {
		atPath := parentName + "." + sa.Name
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

			val := sa.Values[0]

			if !idx.AllowDupKey {
				if idx.HasVal(val, tx) {
					detail := fmt.Sprintf("Uniqueness violation, value %s of attribute %s already exists", val, sa.Name)
					err := base.NewConflictError(detail)
					err.ScimType = base.ST_UNIQUENESS
					panic(err)
				}
			}

			// the SimpleAttributes here will always be single valued
			err = idx.add(val, rid, tx)
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

func findSelectedObj(po *base.PatchOp, tCa *base.ComplexAttribute) []string {
	pp := po.ParsedPath
	offsets := pp.Slctr.Find(tCa)

	if offsets == nil {
		detail := fmt.Sprintf("The selector %s present in the path of operation %d didn't match any attribute", pp.Text, po.Index)
		se := base.NewBadRequestError(detail)
		panic(se)
	}

	return offsets
}

// key is the value of key of the map that is holding the subAtMapS
func deleteAtFromSubAtMap(sl *Silo, pp *base.ParsedPath, tSaMap map[string]*base.SimpleAttribute, key string, ca *base.ComplexAttribute, prIdx *Index, res *base.Resource, rid string, tx *bolt.Tx, mh *modifyHints) {
	numSubObj := len(ca.SubAts)
	rt := res.GetType()
	if sa, ok := tSaMap[pp.AtType.NormName]; ok {
		delete(tSaMap, sa.Name)
		sl.dropSAtFromIndex(sa, ca.Name+"."+sa.Name, prIdx, rt.Name, rid, tx)
		if len(tSaMap) == 0 {
			if numSubObj == 1 {
				res.DeleteAttr(ca.Name)
			} else {
				delete(ca.SubAts, key)
			}
		}

		mh.markDirty()
	}
}

func (sl *Silo) replaceAttrIn(target *base.Resource, attr base.Attribute, tx *bolt.Tx, prIdx *Index, mh *modifyHints) {
	rt := target.GetType()
	rid := target.GetId()
	atType := attr.GetType()

	if atType.IsReadOnly() {
		detail := fmt.Sprintf("Cannot replace read-only attribute %s to resource %s", atType.Name, target.GetId())
		log.Debugf(detail)
		se := base.NewBadRequestError(detail)
		panic(se)
	}

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
				detail := fmt.Sprintf("Cannot replace immutable attribute %s to resource %s, value already exists", atType.Name, target.GetId())
				log.Debugf(detail)
				se := base.NewBadRequestError(detail)
				se.ScimType = base.ST_MUTABILITY
				panic(se)
			}

			// whether multi-valued or not if path is not specified it will be replaced
			sl.dropCAtFromIndex(tCa, prIdx, rt.Name, rid, tx)

			tCa.SubAts = ca.SubAts

			sl.addCAtoIndex(tCa, prIdx, rt.Name, rid, tx)
			mh.markDirty()
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
