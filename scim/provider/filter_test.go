package provider

import (
	"bytes"
	"fmt"
	//logger "github.com/juju/loggo"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func init() {
	//logger.ConfigureLoggers("<root>=debug")
}

func TestSimpleFilter(t *testing.T) {
	var filters = []struct {
		f    string
		pass bool
		op   string // root node's operator name
	}{
		{"(   userName eq \"bje\\\"n\\s en\")", true, "eq"},
		{"userName eq \"bjensen\" and email co \"example.com\"", true, "and"},
		{"not (userName eq \"bjensen\" and email co \"example.com\")", true, "not"},
		{"abc eq 1 and not (userName eq \"bjensen\" and email co \"example.com\")", true, "and"},
		{"xyz eq 1 not (userName eq \"invalid filter\")", false, ""},
		{"abc pr", true, "pr"},
		{"userName eq \"bjensen", false, "eq"},
		{"userType eq \"Employee\" and emails[type eq \"work\" and  value co \"@example.com\"]", true, "and"},
		{"(sCHEmA:e.V pR or (sChEmA:J.i-[h.L- GT nuLl]))", true, "or"},
		{"((SchemA:u.P8 pR))", true, "pr"},
		{"c.W pr", true, "pr"},
		{"(schEma:ct pR And noT(scheMa:Z6 ne nULL) and ScHemA:n_ pr Or ScheMA:b.LZ sw STRIng OR schEma:h.i_-38_- pR anD nOt(o.fu Pr) oR V--7-.z PR)", true, "and"},
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

func TestBnfgenFilter(t *testing.T) {
	for i := 0; i < 1000; i++ {
		filter := bnfgen()
		xpr, err := ParseFilter(filter)
		fmt.Println("parsed filter : ", xpr)
		fmt.Println(err)

		if xpr == nil || err != nil {
			t.Errorf("Failed to parse BNFGEN filter %s", filter)
		}

	}
}

// Generates a valid search filter based on the
// grammar present in filter.abnf using the abnfgen utlity (http://www.quut.com/abnfgen)
func bnfgen() string {
	cmd := exec.Command("/usr/local/bin/abnfgen", "-c")

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	grammar, err := ioutil.ReadFile(wd + "/../../resources/filter.abnf")
	if err != nil {
		panic(err)
	}

	in := bytes.NewBuffer(grammar)
	cmd.Stdin = in

	var out bytes.Buffer

	cmd.Stdout = &out

	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	return string(out.Bytes())
}
