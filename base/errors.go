// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"encoding/json"
	"strconv"
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
	Schemas  []string `json:"schemas"`
	ScimType string   `json:"scimType"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	code     int      // the Status value as an integer
}

func (se *ScimError) Serialize() []byte {
	data, err := json.Marshal(se)
	if err != nil {
		return []byte(err.Error())
	}

	return data
}

func (se *ScimError) Error() string {
	return string(se.Serialize())
}

func NewError() *ScimError {
	return &ScimError{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:Error"}}
}

func NewBadRequestError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 400
	err.Status = strconv.Itoa(err.code)
	return err
}

func NewNotFoundError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 404
	err.Status = strconv.Itoa(err.code)
	return err
}

func NewConflictError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 409
	err.Status = strconv.Itoa(err.code)
	return err
}

func NewInternalserverError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 500
	err.Status = strconv.Itoa(err.code)
	return err
}

func NewForbiddenError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 403
	err.Status = strconv.Itoa(err.code)
	return err
}

func NewUnAuthorizedError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 401
	err.Status = strconv.Itoa(err.code)
	return err
}

func NewPreCondError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 412
	err.Status = strconv.Itoa(err.code)
	return err
}
func NewToomanyResults(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 412
	err.ScimType = ST_TOOMANY
	err.Status = strconv.Itoa(err.code)
	return err
}

func (se ScimError) Code() int {
	return se.code
}
