package silo

import (
	"fmt"
	"sort"
	"sparrow/scim/base"
	"sparrow/scim/schema"
	"strconv"
	"strings"
)

var EMPTY_EV = &EmptyEvaluator{}

var ascendingCountNodes = func(n1, n2 *base.FilterNode) bool {
	return n1.Count < n2.Count
}

var descendingCountNodes = func(n1, n2 *base.FilterNode) bool {
	return n1.Count > n2.Count
}

type Evaluator interface {
	evaluate(rs *base.Resource) bool
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
	node *base.FilterNode
}

type PresenceEvaluator struct {
	node *base.FilterNode
}

type NotEvaluator struct {
	childEv Evaluator
}

func (and *AndEvaluator) evaluate(rs *base.Resource) bool {
	for _, ev := range and.children {
		if !ev.evaluate(rs) {
			return false
		}
	}

	return true
}

func (or *OrEvaluator) evaluate(rs *base.Resource) bool {
	for _, ev := range or.children {
		if ev.evaluate(rs) {
			return true
		}
	}

	return false
}

func (empty *EmptyEvaluator) evaluate(rs *base.Resource) bool {
	return false
}

func (not *NotEvaluator) evaluate(rs *base.Resource) bool {
	return !not.childEv.evaluate(rs)
}

func (pr *PresenceEvaluator) evaluate(rs *base.Resource) bool {
	atType := pr.node.GetAtType()
	if atType == nil {
		return false
	}

	at := rs.GetAttr(pr.node.Name)

	return at != nil
}

func (ar *ArithmeticEvaluator) evaluate(rs *base.Resource) bool {
	return compare(ar.node, rs)
}

func compare(node *base.FilterNode, rs *base.Resource) bool {
	// last para of https://tools.ietf.org/html/rfc7644#section-3.4.2.1
	atType := node.GetAtType()
	if atType == nil {
		return false
	}

	if atType.IsComplex() {
		return false // comaprison should be only on sub-attributes, not on parent
	}

	parentType := atType.Parent()
	if parentType != nil && parentType.MultiValued {
		parentAt := rs.GetAttr(strings.ToLower(parentType.Name))
		if parentAt == nil {
			return false
		}

		atName := strings.ToLower(atType.Name)
		ca := parentAt.GetComplexAt()

		for _, smap := range ca.SubAts {
			if at, ok := smap[atName]; ok {
				sa := at.GetSimpleAt()
				matched := _compare(sa, node, atType)

				if matched {
					return true
				}
			}
		}

		return false
	}

	at := rs.GetAttr(node.Name)

	if at == nil {
		return false
	}

	sa := at.GetSimpleAt()

	return _compare(sa, node, atType)
}

func _compare(sa *base.SimpleAttribute, node *base.FilterNode, atType *schema.AttrType) bool {
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

			case "GT":
				matched = val > nval

			case "LT":
				matched = val < nval

			case "GE":
				matched = val >= nval

			case "LE":
				matched = val <= nval
			}

		case "datetime":
			millis, _ := strconv.ParseInt(val, 10, 64)
			nMillis := node.NormValue.(int64)
			matched = _compareInt(node, millis, nMillis)

		case "integer":
			i, _ := strconv.ParseInt(val, 10, 64)
			nint := node.NormValue.(int64)
			matched = _compareInt(node, i, nint)

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

func _compareInt(node *base.FilterNode, i int64, nint int64) bool {
	matched := false

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

	return matched
}

func buildEvaluator(node *base.FilterNode) Evaluator {

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
		orNs := &nodeSorter{}
		orNs.nodes = make([]*base.FilterNode, len(node.Children))
		copy(orNs.nodes, node.Children)
		orNs.order = descendingCountNodes
		sort.Sort(orNs)
		orEvList := buildEvList(orNs.nodes)
		return &OrEvaluator{children: orEvList}

	case "AND":
		andNs := &nodeSorter{}
		andNs.nodes = make([]*base.FilterNode, len(node.Children))
		copy(andNs.nodes, node.Children)
		andNs.order = ascendingCountNodes
		sort.Sort(andNs)
		andEvList := buildEvList(andNs.nodes)
		return &AndEvaluator{children: andEvList}
	}

	panic(fmt.Errorf("Unknown filter node type %s", node.Op))
}

func buildEvList(children []*base.FilterNode) []Evaluator {
	evList := make([]Evaluator, 0)
	for _, node := range children {
		ev := buildEvaluator(node)
		evList = append(evList, ev)
	}

	return evList
}

type nodeSorter struct {
	nodes []*base.FilterNode
	order func(n1, n2 *base.FilterNode) bool
}

func (ns *nodeSorter) Len() int {
	return len(ns.nodes)
}

func (ns *nodeSorter) Swap(i, j int) {
	ns.nodes[i], ns.nodes[j] = ns.nodes[j], ns.nodes[i]
}

func (ns *nodeSorter) Less(i, j int) bool {
	return ns.order(ns.nodes[i], ns.nodes[j])
}
