// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"encoding/json"
	"fmt"
	"io"
	"sparrow/schema"
	"strings"
)

type PatchReq struct {
	Schemas    []string
	IfMatch    string
	Operations []*PatchOp
}

type PatchOp struct {
	Index      int
	Op         string
	Path       string
	ParsedPath *ParsedPath
	Value      interface{}
}

type ParsedPath struct {
	ParentType     *schema.AttrType // name of the sub-attribute's parent
	AtType         *schema.AttrType // name of the (sub-)attribute
	Schema         string           // the schema of the attribute
	Slctr          Selector         // the selection filter present in the path
	Text           string
	IsExtContainer bool
}

func NewPatchReq() *PatchReq {
	pr := &PatchReq{}
	pr.Schemas = []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}
	pr.Operations = make([]*PatchOp, 0)

	return pr
}

func ParsePatchReq(body io.Reader, rt *schema.ResourceType) (*PatchReq, error) {
	if body == nil {
		return nil, NewBadRequestError("Invalid Patch request data")
	}

	var pr PatchReq
	dec := json.NewDecoder(body)
	err := dec.Decode(&pr)

	if err != nil {
		log.Debugf("Failed to parse the patch request %#v", err)
		return nil, NewBadRequestError(err.Error())
	}

	if len(pr.Operations) == 0 {
		detail := "Invalid patch request, one or more operations must be present"
		log.Debugf(detail)
		return nil, NewBadRequestError(detail)
	}

	for i, po := range pr.Operations {
		po.Op = strings.ToLower(strings.TrimSpace(po.Op))
		po.Path = strings.TrimSpace(po.Path)
		po.Index = i
		pLen := len(po.Path)

		switch po.Op {
		case "add", "replace":
			if po.Value == nil {
				detail := fmt.Sprintf("Invalid patch request, missing value in the %d operation", i)
				log.Debugf(detail)
				return nil, NewBadRequestError(detail)
			}

		case "remove":
			if pLen == 0 {
				detail := fmt.Sprintf("Invalid patch request, missing path in the %d operation", i)
				log.Debugf(detail)
				se := NewBadRequestError(detail)
				se.ScimType = ST_NOTARGET
				return nil, se
			}

		default:
			detail := fmt.Sprintf("Invalid patch request, unknown operation name %s in %d operation", po.Op, i)
			log.Debugf(detail)
			return nil, NewBadRequestError(detail)
		}

		if pLen > 0 {
			pp, err := ParsePath(po.Path, rt)
			if err != nil {
				return nil, err
			}

			po.ParsedPath = pp
		}

	}
	return &pr, nil
}

func ParsePath(path string, rt *schema.ResourceType) (pp *ParsedPath, err error) {

	pp = &ParsedPath{}

	runningPath := path
	selector := ""

	defer func() {
		e := recover()
		if e != nil {
			log.Debugf("Failed to parse path %#v", e)
			pp = nil
			err = e.(error)
		}
	}()

	slctrStrtPos := strings.IndexRune(path, '[')

	if slctrStrtPos == 0 {
		detail := fmt.Sprintf("Invalid attribute path %s, missing parent attribute", path)
		return nil, NewBadRequestError(detail)
	}

	if slctrStrtPos > 0 {
		slctrEndPos := strings.LastIndex(path, "]")
		if slctrEndPos == -1 {
			detail := fmt.Sprintf("Invalid attribute path %s, missing ']' character in the path", path)
			return nil, NewBadRequestError(detail)
		}

		selector = path[:slctrEndPos]

		if len(selector) == 0 {
			detail := fmt.Sprintf("Invalid attribute path %s, empty selector present", path)
			return nil, NewBadRequestError(detail)
		}

		// now append ]
		selector += "]"

		runningPath = path[:slctrStrtPos]
		slctrEndPos++
		if slctrEndPos < len(path) {
			runningPath += path[slctrEndPos:]
		}
	}

	colonPos := strings.LastIndex(runningPath, ":")

	if colonPos > 0 {
		// when colon is present there are two cases
		// 1. an attribute of extension container or
		// 2. the extension container itself as a whole
		assumedContainerPath := runningPath
		uri := path[:colonPos]
		if rt.Schema == uri {
			uri = "" // core schema
		} else {
			found := false
			for _, extSc := range rt.SchemaExtensions {
				if uri == extSc.Schema {
					found = true
					pp.Schema = uri
					break
				} else if assumedContainerPath == extSc.Schema {
					pp.IsExtContainer = true
					pp.Schema = assumedContainerPath
					found = true
					break
				}
			}

			if !found {
				detail := fmt.Sprintf("Unknown schema URI %s in the attribute path %s", uri, path)
				return nil, NewBadRequestError(detail)
			}

			if pp.IsExtContainer {
				return pp, nil
			}
		}

		colonPos++
		if colonPos >= len(path) {
			detail := fmt.Sprintf("Invalid attribute path %s", path)
			return nil, NewBadRequestError(detail)
		}

		runningPath = path[colonPos:]
	}

	dotPos := strings.LastIndex(runningPath, ".")
	if dotPos > colonPos {
		parentName := runningPath[:dotPos]
		dotPos++
		if dotPos >= len(runningPath) {
			detail := fmt.Sprintf("invalid attribute name in the path %s", path)
			return nil, NewBadRequestError(detail)
		}

		pp.ParentType = rt.GetAtType(parentName)
		if pp.ParentType == nil {
			detail := fmt.Sprintf("Unknown complex attribute %s in the path %s", parentName, path)
			return nil, NewBadRequestError(detail)
		}

		atName := runningPath[dotPos:]

		name := parentName + "." + atName
		pp.AtType = rt.GetAtType(name)
		if pp.AtType == nil {
			detail := fmt.Sprintf("Unknown attribute %s in the path %s", name, path)
			return nil, NewBadRequestError(detail)
		}
	} else {
		atName := runningPath
		pp.AtType = rt.GetAtType(atName)
		if pp.AtType == nil {
			detail := fmt.Sprintf("Unknown attribute %s in the path %s", atName, path)
			return nil, NewBadRequestError(detail)
		}
	}

	if len(selector) > 0 {
		slctrNode, err := ParseFilter(selector)
		if err != nil {
			return nil, err
		}
		pp.Text = selector
		pp.Slctr = buildSelector(slctrNode, rt)
	}

	// If the target location is a multi-valued attribute and no filter
	// is specified, the attribute and all values are replaced.
	// from the section https://tools.ietf.org/html/rfc7644#section-3.5.2.3
	// seems to be quite problematic when it comes to handling "members" of a Group
	// what should we do when the path present in any given operation contains no selector
	// for example "members.value" should we reject such operation??
	//	if pp.ParentType != nil {
	//		if pp.ParentType.MultiValued && (pp.Slctr == nil) {
	//
	//		}
	//	}

	return pp, nil
}
