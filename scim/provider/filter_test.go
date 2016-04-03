package provider

import (
	"fmt"
	logger "github.com/juju/loggo"
	"strings"
	"testing"
)

func init() {
	logger.ConfigureLoggers("<root>=debug")
}

func TestSimpleFilter(t *testing.T) {
	var filters = []struct {
		f    string
		pass bool
		op   string // root node name
	}{
		{"(   userName eq \"bje\\\"n\\s en\")", true, "eq"},
		{"userName eq \"bjensen\" and email co \"example.com\"", true, "and"},
		{"not (userName eq \"bjensen\" and email co \"example.com\")", true, "not"},
		{"abc eq 1 and not (userName eq \"bjensen\" and email co \"example.com\")", true, "and"},
		{"xyz eq 1 not (userName eq \"invalid filter\")", false, ""},
		{"abc pr", true, "pr"},
		{"userName eq \"bjensen", false, ""},
	}

	for i, _ := range filters {
		f := filters[i]
		xpr, err := ParseFilter(f.f)
		fmt.Println("parsed filter : ", xpr)
		fmt.Println(err)
		if f.pass {
			if xpr == nil || err != nil {
				t.Errorf("Failed to parse the valid filter at index %s", f.f)
			}

			if xpr.Op != strings.ToUpper(f.op) {
				t.Errorf("Invalid root node, expected '%s' but found '%s' after parsing the filter %s", f.op, xpr.Op, f.f)
			}
		} else {
			if xpr != nil || err == nil {
				t.Errorf("Expected to fail parsing of the filter %s, but it succeeded", f.f)
			}
			// no need to check for the root node name
		}
	}
}
