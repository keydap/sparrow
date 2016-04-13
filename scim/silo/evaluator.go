package silo

import (
	"fmt"
	"sparrow/scim/provider"
	"strconv"
	"strings"
)

var EMPTY_EV = &EmptyEvaluator{}

type Evaluator interface {
	evaluate(rs *provider.Resource) bool
}

type EmptyEvaluator struct {
}

type AndEvaluator struct {
	children []Evaluator
}

type OrEvaluator struct {
	children []Evaluator
}

type ArithmeticEvaluator struct {
	node *provider.FilterNode
}

type PresenceEvaluator struct {
	node *provider.FilterNode
}

type NotEvaluator struct {
	childEv Evaluator
}

func (and *AndEvaluator) evaluate(rs *provider.Resource) bool {
	for _, ev := range and.children {
		if !ev.evaluate(rs) {
			return false
		}
	}

	return true
}

func (or *OrEvaluator) evaluate(rs *provider.Resource) bool {
	for _, ev := range or.children {
		if ev.evaluate(rs) {
			return true
		}
	}

	return false
}

func (empty *EmptyEvaluator) evaluate(rs *provider.Resource) bool {
	return false
}

func (not *NotEvaluator) evaluate(rs *provider.Resource) bool {
	return !not.childEv.evaluate(rs)
}

func (pr *PresenceEvaluator) evaluate(rs *provider.Resource) bool {
	atType := pr.node.GetAtType()
	if atType == nil {
		return false
	}

	at := rs.GetAttr(pr.node.Name)

	return at != nil
}

func (ar *ArithmeticEvaluator) evaluate(rs *provider.Resource) bool {
	return compare(ar.node, rs)
}

func compare(node *provider.FilterNode, rs *provider.Resource) bool {
	// last para of https://tools.ietf.org/html/rfc7644#section-3.4.2.1
	atType := node.GetAtType()
	if atType == nil {
		return false
	}

	if atType.IsComplex() {
		return false // comaprison should be only on sub-attributes, not on parent
	}

	at := rs.GetAttr(node.Name)

	if at == nil {
		return false
	}

	sa := at.GetSimpleAt()
	var matched bool

	for _, val := range sa.Values {

		switch atType.Type {
		case "string":
			if !atType.CaseExact {
				val = strings.ToLower(val)
			}

			nval := node.NormValue.(string)

			switch node.Op {
			case "EQ":
				matched = (val == nval)

			case "NE":
				matched = (val != nval)

			case "CO":
				matched = strings.Contains(val, nval)

			case "SW":
				matched = strings.HasPrefix(val, nval)

			case "EW":
				matched = strings.HasSuffix(val, nval)
			}

		case "integer":
			i, _ := strconv.ParseInt(val, 10, 64)
			nint := node.NormValue.(int64)
			switch node.Op {
			case "EQ":
				matched = (i == nint)

			case "NE":
				matched = (i != nint)

			case "GT":
				matched = (i > nint)

			case "LT":
				matched = (i < nint)

			case "GE":
				matched = (i >= nint)

			case "LE":
				matched = (i <= nint)
			}

		case "decimal":
			f, _ := strconv.ParseFloat(val, 64)
			nfloat := node.NormValue.(float64)
			switch node.Op {
			case "EQ":
				matched = (f == nfloat)

			case "NE":
				matched = (f != nfloat)

			case "GT":
				matched = (f > nfloat)

			case "LT":
				matched = (f < nfloat)

			case "GE":
				matched = (f >= nfloat)

			case "LE":
				matched = (f <= nfloat)
			}
		}

		if matched {
			break
		}
	}

	return matched
}

func buildEvaluator(node *provider.FilterNode) Evaluator {

	if node.Count == 0 {
		return EMPTY_EV
	}

	switch node.Op {
	case "EQ", "NE", "CO", "SW", "EW", "GT", "LT", "GE", "LE":
		return &ArithmeticEvaluator{node: node}

	case "PR":
		return &PresenceEvaluator{node: node}

	case "NOT":
		childEv := buildEvaluator(node.Children[0])
		return &NotEvaluator{childEv: childEv}

	case "OR":
		orEvList := buildEvList(node.Children)
		//TODO sort evaluators based on they scan count, descending order
		return &OrEvaluator{children: orEvList}

	case "AND":
		andEvList := buildEvList(node.Children)
		//TODO sort evaluators based on they scan count, ascending order
		return &AndEvaluator{children: andEvList}
	}

	panic(fmt.Errorf("Unknown filter node type %s", node.Op))
}

func buildEvList(children []*provider.FilterNode) []Evaluator {
	evList := make([]Evaluator, 0)
	for _, node := range children {
		ev := buildEvaluator(node)
		evList = append(evList, ev)
	}

	return evList
}
