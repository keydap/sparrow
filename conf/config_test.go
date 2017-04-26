// Copyright 2017 Keydap. All rights reserved.
// Use of this source code is governed by a Apache
// license that can be found in the LICENSE file.

package conf

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestParseConfig(t *testing.T) {
	ddc := DefaultDomainConfig()
	data, err := json.Marshal(ddc)
	if err != nil {
		t.Error("Failed to marshal the default config")
	}

	fmt.Println(string(data))
}
