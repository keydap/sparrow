package base

import (
	"sparrow/scim/schema"
)

type AuthContext struct {
}

type OpContext struct {
	ClientIP string
	Tenant   string
	Endpoint string
	Rs       *Resource
}

type SearchContext struct {
	ParamFilter    string // the given filter parameter
	Endpoint       string // endpoint used for filtering
	ParamAttrs     string // requested list of attributes
	ParamExclAttrs string // requested list of attributes to be excluded

	Filter   *FilterNode            // the search filter
	ResTypes []*schema.ResourceType // the resource types
	Attrs    []string               // attributes to sent
}

type ListResponse struct {
	TotalResults int64
	Resources    []*Resource
	StartIndex   int64
	ItemsPerPage int
}
