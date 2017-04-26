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
