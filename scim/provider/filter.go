package provider

import (
	"fmt"
	"sparrow/scim/schema"
	"strconv"
	"strings"
)

const (
	READ_ATTR_OR_NOT_NODE = iota
	READ_OP
	READ_VAL
)

var op_map = map[string]int{"EQ": 0, "NE": 1, "CO": 2, "SW": 3, "EW": 4, "GT": 5, "LT": 6, "GE": 7, "LE": 8, "PR": 9, "NOT": 10, "OR": 11, "AND": 12}

// A structure representing a filter expression
type FilterNode struct {
	Op        string
	Name      string
	ResType   *schema.ResourceType // resource type this attribute belongs to
	atType    *schema.AttrType     // access AT type using Getter and Setter
	Value     string
	NormValue interface{}
	Children  []*FilterNode
	Count     int64 // the number of possible entries this node might evaluate
}

type position struct {
	index      int // current position in the rune array
	tokenStart int // position of the beginning of the token, used for information purpose
	state      int // the state required to interpret the current token
}

func ParseFilter(filter string) (expr *FilterNode, err error) {
	log.Debugf("Parsing filter %s", filter)
	pos := &position{index: 0}

	defer func() {
		e := recover()
		if e != nil {
			err = e.(error)
			expr = nil
			log.Debugf("Failed to parse filter %s [%s]", filter, err.Error())
		}
	}()

	filter = strings.TrimSpace(filter)

	return parse([]rune(filter), pos), nil
}

func parse(rb []rune, pos *position) *FilterNode {
	length := (len(rb) - 1)

	var node *FilterNode
	var root *FilterNode

	complexAtBegin := false
	var parentAt string

outer:
	for {
		c := rb[pos.index]
		switch c {
		default:
			t, e := readToken(rb, pos.index, pos)
			if e != nil {
				panic(e)
			}

			// if attribute name contains '[' at the end then treat this as a complex attribute

			switch pos.state {
			case READ_ATTR_OR_NOT_NODE:
				// see if this is NOT operator
				if "NOT" == strings.ToUpper(t) {
					log.Debugf("found NOT expression at pos %d", pos.tokenStart)
					tmp := &FilterNode{Op: "NOT"}
					var tmpRoot *FilterNode

					if root == nil {
						root = node
					}

					if root != nil {
						if !isLogical(root.Op) {
							panic(fmt.Errorf("NOT filter cannot be added to a non-logical node"))
						}
						root.addChild(tmp)
						tmpRoot = root
					}

					pos.index++ // prepare for parsing the next node
					child := parse(rb, pos)
					tmp.addChild(child)

					if tmpRoot == nil {
						tmpRoot = tmp
					}

					root = tmpRoot
					// state remains at READ_ATTR_OR_NOT_NODE
				} else {
					log.Debugf("read at %s", t)

					//valuePath = attrPath "[" valFilter "]" ; FILTER uses sub-attributes of a parent attrPath
					dotPos := strings.IndexRune(t, '[')
					if dotPos > 0 && dotPos < (len(t)-1) {
						if complexAtBegin { // if there exists a prior [ but was not matched with a closing ] then panic
							panic(fmt.Errorf("Invalid filter mismatched square brackets [ and ] starting at pos %d", pos.tokenStart))
						}

						complexAtBegin = true
						parentAt = t[:dotPos]
						t = parentAt + "." + t[dotPos+1:]
					} else if complexAtBegin {
						t = parentAt + "." + t
					}

					node = &FilterNode{}
					node.Name = t

					pos.state = READ_OP
				}

			case READ_OP:
				log.Debugf("read op %s", t)
				op := toOperator(t)

				if isLogical(op) {
					if root == nil {
						root = node
						node = nil
					}

					if root == nil {
						panic(fmt.Errorf("Invalid %s node, missing child", op))
					}

					if root.Op != op {
						tmp := &FilterNode{Op: op}
						tmp.addChild(root)
						root = tmp
					}

					pos.state = READ_ATTR_OR_NOT_NODE
				} else if op == "PR" { // either end of the stream or start of a logical operator must follow this
					node.Op = op
					if root != nil && isLogical(root.Op) {
						root.addChild(node)
					}
					pos.state = READ_OP
				} else if op == "NOT" {
					panic(fmt.Errorf("Misplaced NOT filter"))
				} else {
					node.Op = op
					pos.state = READ_VAL
				}

			case READ_VAL:
				log.Debugf("read val %s", t)
				node.Value = t
				if root != nil && isLogical(root.Op) {
					root.addChild(node)
				}
				pos.state = READ_OP
			}

		case ' ':
			log.Debugf("SPace delimiter")

		case '(':
			// beginning of a group, parse this entirely as a node
			if root != nil {
				tmp := parse(rb, pos)
				if isLogical(root.Op) {
					root.addChild(tmp)
				} else {
					panic(fmt.Errorf("Invalid filter grouping"))
				}
			}

		case ')':
			log.Debugf("terminal )")
			break outer

		case ']':
			if !complexAtBegin {
				panic(fmt.Errorf("Invalid filter, found ] without a complex attribute definition"))
			}
			complexAtBegin = false
			log.Debugf("terminal ]")
		}

		pos.index++

		if pos.index >= length {
			break
		}
	}

	if root == nil {
		root = node
	}

	return root
}

func readToken(rb []rune, start int, pos *position) (token string, err error) {
	var pr rune         // previous rune
	beginAt := start    // preserve the start index
	startQuote := false // beginning of "

	pos.tokenStart = start

	for ; pos.index < len(rb); pos.index++ {
		c := rb[pos.index]
		log.Debugf("parsing token %c", c)
		switch c {
		case ' ':
			if start == pos.index {
				start++
				pos.tokenStart = start
				pr = c
				continue
			} else if !startQuote {
				pos.index--
				return string(rb[start : pos.index+1]), nil
			}

		case '"':
			if !startQuote {
				startQuote = true
				pr = c
				continue
			}

			if startQuote && (pr != '\\') {
				return string(rb[start : pos.index+1]), nil
			}

		case '(', ']', ')': // terminals
			if !startQuote {
				// do not add 1 to the index, this is required to exclude ], ( or ) chars from token
				return string(rb[start:pos.index]), nil
			}
		}

		pr = c
	}

	if startQuote {
		return "", fmt.Errorf("No ending \" found at the end of the token stream starting at position %d", beginAt)
	}

	return string(rb[start:pos.index]), nil
}

func toOperator(op string) string {
	// do not trim the space, if space is present in the token then the readToken() is incorrect
	if strings.ContainsRune(op, ' ') {
		// dev helper
		log.Warningf("operator token '%s' contains a space char", op)
	}

	upperVal := strings.ToUpper(op)
	if _, ok := op_map[upperVal]; !ok {
		panic(fmt.Errorf("Invalid operator %s", op))
	}

	return upperVal
}

func isLogical(op string) bool {
	return op_map[op] >= 11
}

func (fn *FilterNode) GetAtType() *schema.AttrType {
	return fn.atType
}

func (fn *FilterNode) SetAtType(atType *schema.AttrType) {
	fn.NormValue = nil
	fn.atType = atType
	fn.normalize()
}

// make fn.Value as interface{} type then the below parsing is not needed
func (fn *FilterNode) normalize() {
	if fn.atType == nil || len(fn.Value) == 0 {
		return
	}

	switch fn.atType.Type {
	case "string":
		if !fn.atType.CaseExact {
			fn.NormValue = strings.ToLower(fn.Value)
		} else {
			fn.NormValue = fn.Value
		}

	case "integer":
		i, err := strconv.ParseInt(fn.Value, 10, 64)
		if err != nil {
			panic(err)
		}
		fn.NormValue = i

	case "decimal":
		f, err := strconv.ParseFloat(fn.Value, 64)
		if err != nil {
			panic(err)
		}
		fn.NormValue = f
	}
}

func (fn *FilterNode) isEmpty() bool {
	return (len(fn.Name) == 0 || len(fn.Op) == 0)
}

func (fn *FilterNode) addChild(child *FilterNode) {
	if fn.Children == nil {
		fn.Children = make([]*FilterNode, 0)
	}

	fn.Children = append(fn.Children, child)
}

func (fn *FilterNode) String() string {
	if fn.Op == "NOT" {
		return fn.Op + " " + fn.Children[0].String()
	}

	if isLogical(fn.Op) {
		return fn.Children[0].String() + " " + fn.Op + " " + fn.Children[1].String()
	}

	return fn.Name + " " + fn.Op + " " + fn.Value
}
