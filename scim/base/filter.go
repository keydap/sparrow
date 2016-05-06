package base

import (
	"fmt"
	logger "github.com/juju/loggo"
	"sparrow/scim/schema"
	"sparrow/scim/utils"
	"strconv"
	"strings"
	"time"
)

const (
	READ_ATTR_OR_NOT_NODE = iota
	READ_OP
	READ_VAL
)

var op_map = map[string]int{"EQ": 0, "NE": 1, "CO": 2, "SW": 3, "EW": 4, "GT": 5, "LT": 6, "GE": 7, "LE": 8, "PR": 9, "NOT": 10, "OR": 11, "AND": 12}

var log logger.Logger

func init() {
	log = logger.GetLogger("sparrow.scim.base")
}

// A structure representing a filter expression
type FilterNode struct {
	Op        string
	Name      string
	ResType   *schema.ResourceType // resource type this attribute belongs to
	atType    *schema.AttrType     // access AT type using Getter and Setter
	Value     string
	NormValue interface{}
	NvBytes   []byte // the norm value in bytes
	Children  []*FilterNode
	Count     int64 // the number of possible entries this node might evaluate
}

type position struct {
	index      int // current position in the rune array
	tokenStart int // position of the beginning of the token, used for information purpose
	state      int // the state required to interpret the current token
	parenCount int // the count of open parentheses
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

	xpr := parse([]rune(filter), pos)

	if pos.parenCount != 0 {
		// bad filter
		detail := fmt.Sprintf("Invalid filter, parentheses mismatch")
		err := NewBadRequestError(detail)
		return nil, err
	}

	numCh := len(xpr.Children)
	if isLogical(xpr.Op) {
		if numCh != 2 {
			// bad filter
			detail := fmt.Sprintf("Invalid filter, wrong number of operands %d for the operation %s", numCh, xpr.Op)
			err := NewBadRequestError(detail)
			return nil, err
		}
	} else if xpr.Op == "NOT" {
		if numCh != 1 {
			// bad filter
			detail := fmt.Sprintf("Invalid filter, wrong number of operands %d for the operation %s", numCh, xpr.Op)
			err := NewBadRequestError(detail)
			return nil, err
		}
	} else if xpr.Op == "" {
		detail := fmt.Sprintf("Invalid filter")
		err := NewBadRequestError(detail)
		return nil, err
	}

	return xpr, nil
}

func parse(rb []rune, pos *position) *FilterNode {
	length := len(rb)

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
					log.Tracef("found NOT expression at pos %d", pos.tokenStart)
					tmp := &FilterNode{Op: "NOT", Count: -1}
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
					log.Tracef("read at %s", t)

					// the attribute path must be converted to lowercase
					t = strings.ToLower(t)

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

					node = &FilterNode{Count: -1}
					node.Name = t

					pos.state = READ_OP
				}

			case READ_OP:
				log.Tracef("read op %s", t)
				op := toOperator(t)

				if isLogical(op) {
					if root == nil {
						root = node
						node = nil
					}

					if root == nil {
						panic(fmt.Errorf("Invalid %s node, missing child", op))
					}

					tmp := &FilterNode{Op: op, Count: -1}
					tmp.addChild(root)
					root = tmp

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
				log.Tracef("read val %s", t)
				node.Value = stripQuotes(t)
				if root != nil && isLogical(root.Op) {
					root.addChild(node)
				}
				pos.state = READ_OP
			}

		case ' ':
			log.Tracef("SPace delimiter")

		case '(':
			// beginning of a group, parse this entirely as a node
			pos.index++
			pos.parenCount++
			tmp := parse(rb, pos)

			if root != nil && isLogical(root.Op) {
				root.addChild(tmp)
			} else {
				root = tmp
				//panic(fmt.Errorf("Invalid filter grouping"))
			}

		case ')':
			pos.parenCount--
			log.Tracef("terminal )")
			break outer

		case ']':
			if !complexAtBegin {
				panic(fmt.Errorf("Invalid filter, found ] without a complex attribute definition"))
			}
			complexAtBegin = false
			log.Tracef("terminal ]")
		}

		pos.index++

		if pos.index >= length {
			if pos.state == READ_VAL {
				// bad filter
				panic(fmt.Errorf("Invalid filter, missing token at position %d (started at position %d)", pos.index+1, pos.tokenStart+1))
			}

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
		log.Tracef("parsing token %c", c)
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

		case ']': // attribute terminal
			if !startQuote {
				// do not add 1 to the index, this is required to exclude ], ( or ) chars from token
				return string(rb[start:pos.index]), nil
			}

		case '(', ')': // grouping terminals
			if !startQuote {
				// do not add 1 to the index, this is required to exclude ], ( or ) chars from token
				t := string(rb[start:pos.index])
				pos.index--
				return t, nil
			}
		}

		pr = c
	}

	if startQuote {
		return "", fmt.Errorf("No ending \" found at the end of the token stream starting at position %d", beginAt)
	}

	log.Tracef("Returning token from [start:end] [%d:%d] total len %d", start, pos.index, len(rb))
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

func stripQuotes(token string) string {
	if token[0:1] == "\"" {
		token = token[1 : len(token)-1]
		token = strings.Replace(token, "\\\"", "\"", -1)
	}

	return token
}

func (fn *FilterNode) GetAtType() *schema.AttrType {
	return fn.atType
}

func (fn *FilterNode) SetAtType(atType *schema.AttrType) {
	fn.NormValue = nil
	fn.NvBytes = nil
	fn.Count = -1 // should be reset so that we will have accurate count when the ResourceType changes just before scanning
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

		fn.NvBytes = []byte(fn.NormValue.(string))

	case "integer":
		i, err := strconv.ParseInt(fn.Value, 10, 64)
		if err != nil {
			panic(err)
		}
		fn.NormValue = i
		fn.NvBytes = utils.Itob(i)

	case "decimal":
		f, err := strconv.ParseFloat(fn.Value, 64)
		if err != nil {
			panic(err)
		}
		fn.NormValue = f
		fn.NvBytes = utils.Ftob(f)

	case "datetime":
		t, err := time.Parse(time.RFC3339, fn.Value)
		if err != nil {
			panic(err)
		}

		millis := t.UnixNano() / 1000000
		fn.NormValue = millis
		fn.NvBytes = utils.Itob(millis)
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
