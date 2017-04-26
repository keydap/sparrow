// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"fmt"
	"sort"
	"sparrow/schema"
	"strings"
)

func SplitAttrCsv(csv string, rTypes []*schema.ResourceType) (attrMap map[string]int, subAtPresent bool) {
	attrMap = make(map[string]int)
	tokens := strings.Split(csv, ",")

outer:
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "." || strings.HasSuffix(t, ".") { // not a valid attribute name
			continue
		}

		tLen := len(t)
		if tLen == 0 {
			continue
		}

		t = strings.ToLower(t)
		colonPos := strings.LastIndex(t, ":")

		if colonPos > 0 {
			urn := strings.ToLower(t[0:colonPos])

			// the URN is case insensitive here, lookup the corresponding
			// Schema ID from the given ResourceTypes
		schemacheck:
			for _, rt := range rTypes {
				if urn == strings.ToLower(rt.Schema) {
					// this is the core schema, we can skip the URN prefix
					urn = ""
					colonPos++
					if colonPos >= tLen { // this is an invalid attribute, skip it
						continue outer
					}
					break
				} else {
					for _, se := range rt.SchemaExtensions {
						if urn == strings.ToLower(se.Schema) {
							urn = se.Schema
							break schemacheck
						}
					}
				}
			}

			t = urn + t[colonPos:]

			if urn == "" {
				// reset the colonPos so that the check (dotPos > colonPos) will be accurate in this case
				colonPos = -1
			}
		}

		attrMap[t] = 1 // 0 is the default value for non-existing keys, so set the value to 1

		dotPos := strings.LastIndex(t, ".")
		if dotPos > colonPos {
			subAtPresent = true
		}
	}

	if len(attrMap) == 0 {
		return nil, false
	}

	return attrMap, subAtPresent
}

// Converts the given list of attributes to AttributeParam and groups the sub-attributes under
// one parent if applicable.
// For example if "emails.type,emails.value" are requested then an AttributeParam with
// name "emails" will be created with two child attributes "type" and "value"
// This will make filtering the attributes easier
func ConvertToParamAttributes(attrMap map[string]int, subAtPresent bool) []*AttributeParam {

	var atpLst []*AttributeParam

	if subAtPresent {
		tmp := make([]string, len(attrMap))
		count := 0
		for k, _ := range attrMap {
			tmp[count] = k
			count++
		}

		sort.Strings(tmp)

		atpLst = make([]*AttributeParam, 0)
		var prev *AttributeParam

		for _, k := range tmp {
			j := &AttributeParam{}
			j.Name = k

			colonPos := strings.LastIndex(k, ":")
			if colonPos > 0 {
				j.SchemaId = k[0:colonPos]
			}

			dotPos := strings.LastIndex(k, ".")    // call LastIndex() to avoid the possible '.' char in URN
			if dotPos > 0 && (dotPos > colonPos) { // to avoid splitting attribute names that have a '.' in the URN
				if prev == nil || !strings.HasPrefix(k, prev.Name+".") {
					j.Name = j.SchemaId + k[0:dotPos]
					dotPos++
					k = k[dotPos:]

					j.SubAts = make([]string, 1)
					j.SubAts[0] = k
				} else if strings.HasPrefix(k, prev.Name+".") {
					dotPos++
					k = k[dotPos:]

					// the below block makes sure to add sub-attributes only when
					// the parent attribute itself is not requested, for example, "name.formatted, name.givenname"
					// but if "name" is also present in the list then the entire "name" attribute should be listed
					if prev.SubAts != nil {
						prev.SubAts = append(prev.SubAts, k)
					}

					continue
				}
			}

			atpLst = append(atpLst, j)
			prev = j
		}
	} else {
		atpLst = make([]*AttributeParam, len(attrMap))
		count := 0
		for k, _ := range attrMap {
			j := &AttributeParam{}
			j.Name = k

			pos := strings.LastIndex(k, ":")
			if pos > 0 {
				j.SchemaId = k[0:pos]
			}
			atpLst[count] = j
			count++
		}
	}

	return atpLst
}

func FixSchemaUris(node *FilterNode, rTypes []*schema.ResourceType) error {
	colonPos := strings.LastIndex(node.Name, ":")

	if colonPos > 0 {
		t := node.Name
		urn := strings.ToLower(t[0:colonPos])

		// the URN is case insensitive here, lookup the corresponding
		// Schema ID from the given ResourceTypes
	schemacheck:
		for _, rt := range rTypes {
			if urn == strings.ToLower(rt.Schema) {
				// this is the core schema, we can skip the URN prefix
				urn = ""
				colonPos++
				if colonPos >= len(t) { // this is an invalid attribute, skip it
					return fmt.Errorf("Invalid attribute %s in filter ", node.Name)
				}
			} else {
				for _, se := range rt.SchemaExtensions {
					if urn == strings.ToLower(se.Schema) {
						urn = se.Schema
						break schemacheck
					}
				}
			}
		}

		t = urn + t[colonPos:]

		node.Name = t
	}

	if node.Children != nil {
		for _, ch := range node.Children {
			FixSchemaUris(ch, rTypes)
		}
	}

	return nil
}
