package base

import (
	"encoding/json"
)

var (
	TempRedirect      = "307"
	PermRedirect      = "308"
	BadRequest        = "400"
	UnAuthorized      = "401"
	Forbidden         = "403"
	NotFound          = "404"
	Conflict          = "409"
	PreCondFailed     = "412"
	PayloadTooLarge   = "413"
	InternalServerErr = "500"
	NotImplemented    = "501"
)
var (
	ST_INVALIDFILTER = "invalidFilter"
	ST_TOOMANY       = "tooMany"
	ST_UNIQUENESS    = "uniqueness"
	ST_MUTABILITY    = "mutability"
	ST_INVALIDSYNTAX = "invalidSyntax"
	ST_INVALIDPATH   = "invalidPath"
	ST_NOTARGET      = "noTarget"
	ST_INVALIDVALUE  = "invalidValue"
	ST_INVALIDVERS   = "invalidVers"
	ST_SENSITIVE     = "sensitive"
)

type ScimError struct {
	Schemas  []string
	ScimType string
	Detail   string
	Status   string
	code     int // the Status value as an integer
}

func (se *ScimError) Error() string {
	data, err := json.Marshal(se)

	if err != nil {
		return err.Error()
	}

	return string(data)
}

func NewError() *ScimError {
	return &ScimError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}}
}

func NewBadRequestError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.Status = "400"
	err.code = 400
	return err
}

func NewNotFoundError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.Status = "404"
	err.code = 404
	return err
}

func NewConflictError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.Status = "409"
	err.code = 409
	return err
}

func (se ScimError) Code() int {
	return se.code
}
