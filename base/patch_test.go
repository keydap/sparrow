// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"bytes"
	"fmt"
	"testing"
)

func TestParsingInvalidPatchReq(t *testing.T) {
	rt := rTypesMap["User"]
	patches := []string{
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"add", "path":"emails", "value":null}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"replace", "path":"emails", "value":null}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "value":null}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"xyz", "path":"emails", "value":null}]}`,
		// invalid paths
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove"}]}`, // no path
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails["}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails]"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails[type ]"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails[type eq]"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails[type eq"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails[type ab"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails[type eq \"work\"].xy"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails[type eq 1].val"}]}`,
	}

	for i, p := range patches {
		reader := bytes.NewReader([]byte(p))
		_, err := ParsePatchReq(reader, rt)
		if err == nil {
			t.Errorf("Failed to parse %d request %s", i, p)
		} else if _, ok := err.(*ScimError); !ok {
			fmt.Println(err)
			panic("Error is not a ScimError")
		}
	}
}

func TestParsingValidPatchReq(t *testing.T) {
	rt := rTypesMap["User"]
	patches := []string{
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"add", "path":"emails", "value":\"a@x.com\"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"replace", "path":"emails[value eq \"x\" or type \"work\"].value", "value":\"abc\"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"remove", "path":"emails[value eq \"x\" or type \"work\"].value"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations":[{"op":"replace", "path":"emails[value eq \"x\" AND type \"work\"].value", "value":\"abc\"}]}`,
	}

	for i, p := range patches {
		reader := bytes.NewReader([]byte(p))
		_, err := ParsePatchReq(reader, rt)
		if err != nil {
			t.Errorf("Failed to parse valid %d request %s", i, p)
		}
	}
}
