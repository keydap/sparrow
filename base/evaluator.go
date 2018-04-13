// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"fmt"
	"sort"
	"sparrow/schema"
	"strings"
)

var EMPTY_EV = &EmptyEvaluator{}

var ascendingCountNodes = func(n1, n2 *FilterNode) bool {
	return n1.Count < n2.Count
}

var descendingCountNodes = func(n1, n2 *FilterNode) bool {
	return n1.Count > n2.Count
}

type Evaluator interface {
	Evaluate(rs *Resource) bool
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
	node *FilterNode
}

type PresenceEvaluator struct {
	node *FilterNode
}

type NotEvaluator struct {
	childEv Evaluator
}

func (and *AndEvaluator) Evaluate(rs *Resource) bool {
	for _, ev := range and.children {
		if !ev.Evaluate(rs) {
			return false
		}
	}

	return true
}

func (or *OrEvaluator) Evaluate(rs *Resource) bool {
	for _, ev := range or.children {
		if ev.Evaluate(rs) {
			return true
		}
	}

	return false
}

func (empty *EmptyEvaluator) Evaluate(rs *Resource) bool {
	return false
}

func (not *NotEvaluator) Evaluate(rs *Resource) bool {
	return !not.childEv.Evaluate(rs)
}

func (pr *PresenceEvaluator) Evaluate(rs *Resource) bool {
	atType := pr.node.GetAtType()
	if atType == nil {
		return false
	}

	at := rs.GetAttr(pr.node.Name)

	return at != nil
}

func (ar *ArithmeticEvaluator) Evaluate(rs *Resource) bool {
	_, result := rsCompare(ar.node, rs)
	return result
}

func rsCompare(node *FilterNode, rs *Resource) (sa *SimpleAttribute, result bool) {
	// last para of https://tools.ietf.org/html/rfc7644#section-3.4.2.1
	atType := node.GetAtType()
	if atType == nil {
		return nil, false
	}

	if atType.IsComplex() {
		return nil, false // comaprison should be only on sub-attributes, not on parent
	}

	parentType := atType.Parent()
	if parentType != nil && parentType.MultiValued {
		parentAt := rs.GetAttr(parentType.NormName)
		if parentAt == nil {
			return nil, false
		}

		atName := atType.NormName
		ca := parentAt.GetComplexAt()

		for _, smap := range ca.SubAts {
			if at, ok := smap[atName]; ok {
				sa = at.GetSimpleAt()
				matched := _compare(sa, node, atType)

				if matched {
					return sa, true
				}
			}
		}

		return nil, false
	}

	at := rs.GetAttr(node.Name)

	if at == nil {
		return nil, false
	}

	sa = at.GetSimpleAt()

	return sa, _compare(sa, node, atType)
}

func _compare(sa *SimpleAttribute, node *FilterNode, atType *schema.AttrType) bool {
	var matched bool

	for _, iVal := range sa.Values {

		switch atType.Type {
		case "string", "reference", "binary":
			val := iVal.(string)

			if (atType.Type == "string") && !atType.CaseExact {
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
			millis := iVal.(int64)
			nMillis := node.NormValue.(int64)
			matched = _compareInt(node, millis, nMillis)

		case "integer":
			i := iVal.(int64)
			nint := node.NormValue.(int64)
			matched = _compareInt(node, i, nint)

		case "decimal":
			f := iVal.(float64)
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

		case "boolean":
			val := iVal.(bool)

			nval := node.NormValue.(bool)

			switch node.Op {
			case "EQ":
				matched = (val == nval)

			case "NE":
				matched = (val != nval)
			}
		}

		if matched {
			break
		}
	}

	return matched
}

func _compareInt(node *FilterNode, i int64, nint int64) bool {
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

func BuildEvaluator(node *FilterNode) Evaluator {

	if node.Count == 0 {
		return EMPTY_EV
	}

	switch node.Op {
	case "EQ", "NE", "CO", "SW", "EW", "GT", "LT", "GE", "LE":
		return &ArithmeticEvaluator{node: node}

	case "PR":
		return &PresenceEvaluator{node: node}

	case "NOT":
		childEv := BuildEvaluator(node.Children[0])
		return &NotEvaluator{childEv: childEv}

	case "OR":
		orNs := &nodeSorter{}
		orNs.nodes = make([]*FilterNode, len(node.Children))
		copy(orNs.nodes, node.Children)
		orNs.order = descendingCountNodes
		sort.Sort(orNs)
		orEvList := buildEvList(orNs.nodes)
		return &OrEvaluator{children: orEvList}

	case "AND":
		andNs := &nodeSorter{}
		andNs.nodes = make([]*FilterNode, len(node.Children))
		copy(andNs.nodes, node.Children)
		andNs.order = ascendingCountNodes
		sort.Sort(andNs)
		andEvList := buildEvList(andNs.nodes)
		return &AndEvaluator{children: andEvList}
	}

	panic(fmt.Errorf("Unknown filter node type %s", node.Op))
}

func buildEvList(children []*FilterNode) []Evaluator {
	evList := make([]Evaluator, 0)
	for _, node := range children {
		ev := BuildEvaluator(node)
		evList = append(evList, ev)
	}

	return evList
}

type nodeSorter struct {
	nodes []*FilterNode
	order func(n1, n2 *FilterNode) bool
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
