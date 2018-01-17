// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"sparrow/schema"
)

type OpContext struct {
	Session  *RbacSession
	Sso      bool
	ClientIP string
	Endpoint string
}

type CreateContext struct {
	InRes      *Resource
	*OpContext // the operation context
}

type GetContext struct {
	Rid        string
	Username   string
	Rt         *schema.ResourceType
	*OpContext // the operation context
}

type DeleteContext struct {
	Rid        string
	Rt         *schema.ResourceType
	*OpContext // the operation context
}

type ReplaceContext struct {
	Rid         string
	InRes       *Resource
	IfNoneMatch string
	Rt          *schema.ResourceType
	*OpContext  // the operation context
}

type PatchContext struct {
	Rid        string
	Pr         *PatchReq
	Rt         *schema.ResourceType
	*OpContext // the operation context
}

type SearchContext struct {
	ParamFilter    string                 // the given filter parameter
	ParamAttrs     string                 // requested list of attributes
	ParamExclAttrs string                 // requested list of attributes to be excluded
	MaxResults     int                    // the maximum number of results returned for a search request
	Filter         *FilterNode            // the search filter
	ResTypes       []*schema.ResourceType // the resource types
	Attrs          []string               // attributes to sent
	*OpContext                            // the operation context
}

type ListResponse struct {
	TotalResults int64
	Resources    []*Resource
	StartIndex   int64
	ItemsPerPage int
}

type AttributeParam struct {
	Name     string
	SchemaId string
	SubAts   map[string]string // simplifies searching and eliminates iteration while filtering denied attributes
}

// https://tools.ietf.org/html/rfc7644#section-3.4.3
type SearchRequest struct {
	Schemas            []string `json:"schemas"`
	Attributes         string   `json:"attributes"`
	ExcludedAttributes string   `json:"excludedAttributes"`
	Filter             string   `json:"filter"`
	SortBy             string   `json:"sortBy"`
	SortOrder          string   `json:"sortOrder"`
	StartIndex         int      `json:"startIndex"`
	Count              int      `json:"count"`
}

type AuthRequest struct {
	Username string
	Domain   string
	Password string
	ClientIP string
}

type OpDecision struct {
	Allow            bool
	Deny             bool
	EvalWithoutFetch bool
	EvalFilter       bool
}

func NewSearchRequest(filter string, attrs string, include bool) *SearchRequest {
	req := &SearchRequest{}
	req.Schemas = []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"}
	req.Filter = filter

	if len(attrs) > 0 {
		if include {
			req.Attributes = attrs
		} else {
			req.ExcludedAttributes = attrs
		}
	}

	return req
}

func (cc *CreateContext) AllowOp() bool {
	rt := cc.InRes.resType
	rp := cc.Session.EffPerms[rt.Name]
	if rp == nil {
		return false
	}

	if rp.WritePerm.OnAnyResource && rp.WritePerm.AllowAll {
		return true
	}

	entryOk := rp.WritePerm.EvalFilter(cc.InRes)

	return entryOk && rp.WritePerm.AllowAll
}

func (dc *DeleteContext) EvalDelete(res *Resource) bool {
	rp := dc.Session.EffPerms[dc.Rt.Name]
	if rp == nil {
		return false
	}

	if !rp.ReadPerm.AllowAll {
		return false
	}

	return rp.ReadPerm.EvalFilter(res)
}

func (dc *DeleteContext) GetDecision() OpDecision {
	od := OpDecision{}
	rp := dc.Session.EffPerms[dc.Rt.Name]
	if rp == nil {
		od.Deny = true
		return od
	}

	if rp.WritePerm.OnAnyResource && rp.WritePerm.AllowAll {
		od.Allow = true
	} else {
		od.EvalFilter = true
	}
	return od
}

func (pc *PatchContext) GetDecision() OpDecision {
	od := OpDecision{}
	// special case for patching self
	if pc.Rid == pc.Session.Sub {
		od.EvalFilter = true
		return od
	}

	rp := pc.Session.EffPerms[pc.Rt.Name]
	if rp == nil {
		od.Deny = true
		return od
	}

	if rp.WritePerm.OnAnyResource && rp.WritePerm.AllowAll {
		od.Allow = true
	} else if rp.WritePerm.OnAnyResource {
		od.EvalWithoutFetch = true
	} else {
		od.EvalFilter = true
	}

	return od
}

func (pc *PatchContext) EvalPatch(res *Resource) bool {

	// special case for allowing self-password change
	if pc.Rid == pc.Session.Sub {
		if len(pc.Pr.Operations) == 1 { // there must be only one operation
			op := pc.Pr.Operations[0]
			if op.Path == "password" {
				return true
			}
		}
	}

	rp := pc.Session.EffPerms[pc.Rt.Name]
	if rp.WritePerm == nil {
		return false
	}

	entryOk := true
	if res != nil { // will be nil IF EvalWithoutFetch is true
		entryOk = rp.WritePerm.EvalFilter(res)
	}

	if entryOk && rp.WritePerm.AllowAll {
		return true
	}

	allowAttrs := rp.WritePerm.AllowAttrs
	for _, po := range pc.Pr.Operations {
		if po.ParsedPath.ParentType != nil {
			at := allowAttrs[po.ParsedPath.ParentType.NormName]
			if at == nil {
				return false
			} else {
				if at.SubAts != nil { // check sub attributes are allowed
					_, ok := at.SubAts[po.ParsedPath.AtType.NormName]
					if !ok {
						return false
					}
				}
			}
		} else {
			at := allowAttrs[po.ParsedPath.AtType.NormName]
			if at == nil {
				return false
			}
		}
	}

	return entryOk
}

func (gc *GetContext) GetDecision() OpDecision {
	od := OpDecision{}
	rp := gc.Session.EffPerms[gc.Rt.Name]
	if rp == nil {
		od.Deny = true
		return od
	}

	if rp.ReadPerm.OnAnyResource {
		od.Allow = true
	} else {
		od.EvalFilter = true
	}
	return od
}

func (gc *GetContext) AllowRead(res *Resource) bool {
	rp := gc.Session.EffPerms[gc.Rt.Name]
	if rp == nil {
		return false
	}

	if !rp.ReadPerm.AllowAll && rp.ReadPerm.AllowAttrs == nil {
		return false
	}

	return rp.ReadPerm.EvalFilter(res)
}

func (rc *ReplaceContext) AllowOp() bool {
	rp := rc.Session.EffPerms[rc.Rt.Name]
	if rp == nil {
		return false
	}

	if !rp.WritePerm.AllowAll {
		return false
	}

	if rp.WritePerm.OnAnyResource {
		return true
	}

	return rp.WritePerm.EvalFilter(rc.InRes)
}

func (sc *SearchContext) CanDenyOp() (bool, *FilterNode) {
	rtLen := len(sc.ResTypes)

	// use 1 less than the count cause the
	// for loop runs from 0 to rtLen-1
	powTwo := (1 << uint(rtLen-1))
	flipped := powTwo
	var fn *FilterNode
	for i, rt := range sc.ResTypes {
		efp := sc.Session.EffPerms[rt.Name]
		if efp == nil {
			// flip the bit at ith index
			flipped ^= (1 << uint(i))
		} else if !efp.ReadPerm.OnAnyResource {
			tmp := efp.ReadPerm.Filter
			if tmp == nil {
				flipped ^= (1 << uint(i))
				continue
			}

			tmp = tmp.Clone()
			if fn == nil {
				if rtLen > 1 {
					fn = &FilterNode{Op: "OR"}
					fn.Children = make([]*FilterNode, 1)
					fn.Children[0] = tmp
				} else {
					fn = tmp
				}
			} else {
				fn.Children = append(fn.Children, tmp)
			}
		}
	}

	deny := ((flipped & powTwo) == 0)
	return deny, fn
}
