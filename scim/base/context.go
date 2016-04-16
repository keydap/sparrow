package base

import (
	"sparrow/scim/schema"
)

type AuthContext struct {
}

type OpContext struct {
}

type SearchContext struct {
	ParamFilter string // the given filter parameter
	Endpoint    string // endpoint used for filtering

	Filter   *FilterNode
	ResTypes []*schema.ResourceType
}
