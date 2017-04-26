// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package base

import (
	"bytes"
	//	"fmt"
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
		{`(   userName eq "bje\"n\\s en")`, true, "eq"},
		{`userName eq "bjensen" and email co "example.com"`, true, "and"},
		{`not (userName eq "bjensen" and email co "example.com")`, true, "not"},
		{`abc eq 1 and not (userName eq "bjensen" and email co "example.com")`, true, "and"},
		{`xyz eq 1 not (userName eq "invalid filter")`, false, ""},
		{`abc pr`, true, "pr"},
		{`userName eq "bjensen`, false, "eq"},
		{`userType eq "Employee" and emails[type eq "work" and  value co "@example.com"]`, true, "and"},
		{`(sCHEmA:e.V pR or (sChEmA:J.i-[h.L- GT nuLl]))`, true, "or"},
		{`((SchemA:u.P8 pR))`, true, "pr"},
		{`c.W pr`, true, "pr"},
		{`(schEma:ct pR And noT(scheMa:Z6 ne nULL) and ScHemA:n_ pr Or ScheMA:b.LZ sw STRIng OR schEma:h.i_-38_- pR anD nOt(o.fu Pr) oR V--7-.z PR)`, true, "and"},
		{`userType eq "Employee" and (emails co "example.com" or emails.value co "example.org") AND abc eq bj`, true, "and"},
	}

	for i, _ := range filters {
		f := filters[i]
		xpr, err := ParseFilter(f.f)
		//		fmt.Println("parsed filter : ", xpr)
		//		fmt.Println(err)
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

func TestNodeHierarchy(t *testing.T) {
	s := `userName eq "bjensen" and (emails eq "k@example.com" and (im eq "z" and id eq "1" ))`
	xpr, err := ParseFilter(s)
	//fmt.Println("parsed filter : ", xpr)
	if err != nil {
		t.Error(err)
	}

	if len(xpr.Children) != 2 {
		t.Errorf("Expected number of children are not present")
	}

	if xpr.Children[0].Op != "EQ" || xpr.Children[0].Name != "username" {
		t.Errorf("wrong first child")
	}

	child2 := xpr.Children[1]
	if child2.Op != "AND" {
		t.Errorf("wrong second child")
	}

	child21 := child2.Children[0]
	if child21.Op != "EQ" || child21.Name != "emails" {
		t.Errorf("wrong second child's AND node's left node")
	}

	child22 := child2.Children[1]
	if child22.Op != "AND" {
		t.Errorf("wrong second child's AND node's right node")
	}

	child221 := child22.Children[0]
	if child221.Op != "EQ" || child221.Name != "im" {
		t.Errorf("wrong second child's AND node's left child")
	}

	child222 := child22.Children[1]
	if child222.Op != "EQ" || child222.Name != "id" {
		t.Errorf("wrong second child's AND node's right child")
	}
}

func TestParentheses(t *testing.T) {
	s := "(emails.type co \"home\" and username co \"ss\" )and displayname sw \"j\""
	xpr, err := ParseFilter(s)

	if xpr.Children[1].Name != "displayname" {
		t.Errorf("Incorrect parse tree when parentheses are present [%#v]", err)
	}

	s = "(emails.type co \"home\" and (username co \"ss\")) and displayname sw \"j\""
	xpr, err = ParseFilter(s)

	if xpr.Children[1].Name != "displayname" {
		t.Errorf("Incorrect parse tree when parentheses are present [%#v]", err)
	}

	s = "(emails.type co \"home\" and username co \"ss\") and (displayname sw \"j\" or email.value co \"org\")"
	xpr, err = ParseFilter(s)

	if xpr.Children[1].Children[0].Name != "displayname" || xpr.Children[1].Children[1].Name != "email.value" {
		t.Errorf("Incorrect parse tree when parentheses are present [%#v]", err)
	}

	// same as above but with multiple (())
	s = "((emails.type co \"home\") and (username co \"ss\")) and (((displayname sw \"j\") or (email.value co \"org\")))"
	xpr, err = ParseFilter(s)

	if xpr.Children[1].Children[0].Name != "displayname" || xpr.Children[1].Children[1].Name != "email.value" {
		t.Errorf("Incorrect parse tree when parentheses are present [%#v]", err)
	}

	// incorrect parentheses
	s = "((emails.type co \"home\" and (username co \"ss\")) and displayname sw \"j\""
	xpr, err = ParseFilter(s)

	if err == nil {
		t.Errorf("Incorrect parse tree %#v", err)
	}

	xpr, err = ParseFilter("(and)")
	if err == nil {
		t.Errorf("Incorrect and filter %#v", err)
	}

	xpr, err = ParseFilter("(username eq)")
	if err == nil {
		t.Errorf("Incorrect equality filter %#v", err)
	}

	xpr, err = ParseFilter("(username pr)")
	if err != nil {
		t.Errorf("Incorrect presence filter %#v", err)
	}
}

func TestBnfgenFilter(t *testing.T) {
	if true {
		//return
	}

	for i := 0; i < 1000; i++ {
		filter := bnfgen()
		xpr, err := ParseFilter(filter)
		//		fmt.Println("parsed filter : ", xpr)
		//		fmt.Println(err)

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

	grammar, err := ioutil.ReadFile(wd + "/../resources/filter.abnf")
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
