package base

import (
	"fmt"
	"sparrow/scim/schema"
)

type Selector interface {
	Find(ca *ComplexAttribute) []int
}

type AndSelector struct {
	children []Selector
}

type OrSelector struct {
	children []Selector
}

type ArithmeticSelector struct {
	node *FilterNode
}

type PresenceSelector struct {
	node *FilterNode
}

type NotSelector struct {
	childEv Selector
}

func (and *AndSelector) Find(ca *ComplexAttribute) []int {
	indices := make([]int, len(ca.SubAts))
	first := true

	for _, ev := range and.children {
		childIndices := ev.Find(ca)
		if childIndices == nil {
			return nil
		}

		if first {
			for _, i := range childIndices {
				indices[i] = 1
			}
			first = false
		} else {
			for _, i := range childIndices {
				indices[i] &= 1
			}
		}
	}

	finalIndices := make([]int, 0)
	for i, v := range indices {
		if v == 1 {
			finalIndices = append(finalIndices, i)
		}
	}

	if len(finalIndices) == 0 {
		finalIndices = nil
	}

	return finalIndices
}

func (not *NotSelector) Find(ca *ComplexAttribute) []int {
	return not.childEv.Find(ca)
}

func (pr *PresenceSelector) Find(ca *ComplexAttribute) []int {
	atType := pr.node.GetAtType()
	indices := make([]int, 0)
	for i, subAtMap := range ca.SubAts {
		sa := subAtMap[atType.NormName]
		if sa != nil {
			indices = append(indices, i)
		}
	}

	if len(indices) == 0 {
		indices = nil
	}

	return indices
}

func (or *OrSelector) Find(ca *ComplexAttribute) []int {
	return nil
}

func (ar *ArithmeticSelector) Find(ca *ComplexAttribute) []int {
	return caCompare(ar.node, ca)
}

func caCompare(node *FilterNode, ca *ComplexAttribute) []int {
	indices := make([]int, 0)
	for i, subAtMap := range ca.SubAts {
		sa := subAtMap[node.atType.NormName]
		if sa != nil {
			matched := _compare(sa, node, sa.atType)
			if matched {
				indices = append(indices, i)
			}
		}
	}

	if len(indices) == 0 {
		indices = nil
	}

	return indices
}

func buildSelector(node *FilterNode, rt *schema.ResourceType) Selector {
	switch node.Op {
	case "EQ", "NE", "CO", "SW", "EW", "GT", "LT", "GE", "LE":
		atType := rt.GetAtType(node.Name)
		if atType == nil {
			detail := fmt.Sprintf("Attribute %s present in the path selector is not found in the resource type %s", node.Name, rt.Name)
			panic(NewNotFoundError(detail))
		}
		node.SetAtType(atType)
		return &ArithmeticSelector{node: node}

	case "PR":
		atType := rt.GetAtType(node.Name)
		if atType == nil {
			detail := fmt.Sprintf("Attribute %s present in the path selector is not found in the resource type %s", node.Name, rt.Name)
			panic(NewNotFoundError(detail))
		}
		node.SetAtType(atType)
		return &PresenceSelector{node: node}

	case "NOT":
		childEv := buildSelector(node.Children[0], rt)
		return &NotSelector{childEv: childEv}

	case "OR":
		orEvList := buildSlctrList(node.Children, rt)
		return &OrSelector{children: orEvList}

	case "AND":
		andEvList := buildSlctrList(node.Children, rt)
		return &AndSelector{children: andEvList}
	}

	panic(fmt.Errorf("Unknown selector node type %s", node.Op))
}

func buildSlctrList(children []*FilterNode, rt *schema.ResourceType) []Selector {
	evList := make([]Selector, 0)
	for _, node := range children {
		ev := buildSelector(node, rt)
		evList = append(evList, ev)
	}

	return evList
}
