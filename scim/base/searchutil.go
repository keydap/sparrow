package base

import (
	"sort"
	"sparrow/scim/schema"
	"strings"
)

func SplitAttrCsv(csv string, rTypes []*schema.ResourceType) (attrMap map[string]int, subAtPresent bool) {
	attrMap = make(map[string]int)
	tokens := strings.Split(csv, ",")

outer:
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "." { // not a valid attribute name
			continue
		}

		tLen := len(t)
		if tLen == 0 {
			continue
		}

		t = strings.ToLower(t)

		if strings.ContainsRune(t, ':') {
			pos := strings.LastIndex(t, ":")
			urn := strings.ToLower(t[0:pos])

			// the URN is case insensitive here, lookup the corresponding
			// Schema ID from the given ResourceTypes
		schemacheck:
			for _, rt := range rTypes {
				if urn == strings.ToLower(rt.Schema) {
					// this is the core schema, we can skip the URN prefix
					urn = ""
					pos++
					if pos >= tLen { // this is an invalid attribute, skip it
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

			t = urn + t[pos:]
		}

		attrMap[t] = 1 // 0 is the default value for non-existing keys, so set the value to 1

		if strings.ContainsRune(t, '.') {
			subAtPresent = true
		}
	}

	if len(attrMap) == 0 {
		return nil, false
	}

	return attrMap, subAtPresent
}

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

			pos := strings.LastIndex(k, ":")
			if pos > 0 {
				j.SchemaId = k[0:pos]
			}

			if prev != nil {
				pos = strings.IndexRune(k, '.')
				if pos > 0 {
					if strings.HasPrefix(k, prev.Name+".") {
						pos++
						if pos >= len(k) {
							// invalid sub attribute
							continue
						}

						k = k[pos:]

						if prev.SubAts == nil {
							prev.SubAts = make([]string, 0)
						}

						prev.SubAts = append(prev.SubAts, k)
						continue
					}
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
