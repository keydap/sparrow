// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"encoding/json"
	"net/http"
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
	ST_INVALIDFILTER          = "invalidFilter"
	ST_TOOMANY                = "tooMany"
	ST_UNIQUENESS             = "uniqueness"
	ST_MUTABILITY             = "mutability"
	ST_INVALIDSYNTAX          = "invalidSyntax"
	ST_INVALIDPATH            = "invalidPath"
	ST_NOTARGET               = "noTarget"
	ST_INVALIDVALUE           = "invalidValue"
	ST_INVALIDVERS            = "invalidVers"
	ST_SENSITIVE              = "sensitive"
	ST_PEER_CONNECTION_FAILED = "failed to connect to peer"
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
	err.Status = BadRequest
	return err
}

func NewNotFoundError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 404
	err.Status = NotFound
	return err
}

func NewConflictError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 409
	err.Status = Conflict
	return err
}

func NewInternalserverError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 500
	err.Status = InternalServerErr
	return err
}

func NewForbiddenError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 403
	err.Status = Forbidden
	return err
}

func NewUnAuthorizedError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 401
	err.Status = UnAuthorized
	return err
}

func NewPreCondError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 412
	err.Status = PreCondFailed
	return err
}

func NewToomanyResults(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 413
	err.ScimType = ST_TOOMANY
	err.Status = err.ScimType
	return err
}

func NewPeerConnectionFailed(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.code = 520
	err.ScimType = ST_PEER_CONNECTION_FAILED
	err.Status = err.ScimType
	return err
}

func (se ScimError) Code() int {
	return se.code
}

func NewFromHttpResp(resp *http.Response) *ScimError {
	detail := resp.Status
	switch resp.StatusCode {
	case 400:
		return NewBadRequestError(detail)
	case 401:
		return NewUnAuthorizedError(detail)
	case 403:
		return NewForbiddenError(detail)
	case 404:
		return NewNotFoundError(detail)
	case 409:
		return NewConflictError(detail)
	case 412:
		return NewPreCondError(detail)
	case 413:
		return NewToomanyResults(detail)
	default:
		return NewInternalserverError("(unknown/unmapped status code) " + detail)
	}
}
