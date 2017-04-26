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
	SubAts   []string
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
