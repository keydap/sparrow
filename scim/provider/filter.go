package provider

import (
	"fmt"
	"sparrow/scim/schema"
	"strings"
)

const (
	READ_ATTR_OR_NOT_NODE = iota
	READ_ATTR
	READ_OP
	READ_VAL
)

var op_map = map[string]int{"EQ": 0, "NE": 1, "CO": 2, "SW": 3, "EW": 4, "GT": 5, "LT": 6, "GE": 7, "LE": 8, "PR": 9, "NOT": 10, "OR": 11, "AND": 12}

// A structure representing a filter expression
type FilterNode struct {
	Op       string
	Name     string
	AtType   *schema.AttrType
	Value    string
	Children []*FilterNode
}

type position struct {
	//runes []rune
	index      int
	tokenStart int // position of the beginning of the token, used for information purpose
	state      int
}

/*func (rb *runeBuf) hasMore() bool {
	return rb.index < len(rb.runes)
}

func (rb *runeBuf) prevRune() rune {
	if rb.index == 0 {
		return -1
	}

	return rb.runes[rb.index - 1]
}

func (rb *runeBuf) nextRune() rune {
	rb.index++
	return rb.runes[rb.index]
}*/

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

	return parse([]rune(filter), pos, nil), nil
}

func parse(rb []rune, pos *position, root *FilterNode) *FilterNode {
	length := (len(rb) - 1)

	var node *FilterNode
	node = nil

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

					pos.index++ // preparse for parsing the next node
					child := parse(rb, pos, nil)
					tmp.addChild(child)

					if tmpRoot == nil {
						tmpRoot = tmp
					}

					root = tmpRoot
					// state remains at READ_ATTR_OR_NOT_NODE
				} else {
					log.Debugf("read at %s", t)
					node = &FilterNode{}
					node.Name = t
					pos.state = READ_OP
				}

			case READ_ATTR:
				log.Debugf("read at %s", t)
				node = &FilterNode{}
				node.Name = t
				pos.state = READ_OP

			case READ_OP:
				log.Debugf("read op %s", t)
				op := toOperator(t)

				if isLogical(op) {
					tmp := &FilterNode{Op: op}

					if root == nil {
						root = node
					}

					if root != nil {
						tmp.addChild(root)
						root = tmp
						node = nil
					} else {
						panic(fmt.Errorf("Invalid %s node, missing child", op))
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
			fmt.Println("SPace delimiter")

		case '(', ')':
			fmt.Println("terminal")

		case '[', ']':
			fmt.Println("terminal")
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

		case '[':
			if !startQuote {
				return string(rb[start : pos.index+1]), nil
			}
		}

		pr = c
	}
	
	if startQuote {
		return "", fmt.Errorf("No ending \" found at the end of the token stream starting at position %d", beginAt)
	}

	return string(rb[start : pos.index]), nil
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
