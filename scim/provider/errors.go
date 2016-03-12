package provider

import (
	"encoding/json"
)

type ScimError struct {
	Schemas  []string
	ScimType string
	Detail   string
	Status   string
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
	return err
}

func NewNotFoundError(detail string) *ScimError {
	err := NewError()
	err.Detail = detail
	err.Status = "404"
	return err
}
