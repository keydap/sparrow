package base

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sparrow/scim/schema"
	"strings"
)

type PatchReq struct {
	Schemas    []string
	Operations []*PatchOp
}

type PatchOp struct {
	Index      int
	Op         string
	Path       string
	ParsedPath *ParsedPath
	Value      interface{}
}

type ParsedPath struct {
	ParentType *schema.AttrType // name of the sub-attribute's parent
	AtType     *schema.AttrType // name of the (sub-)attribute
	Schema     string           // the schema of the attribute
	SlctrType  *schema.AttrType // name of the selector sub-attribute
	SlctrVal   interface{}      // value of the selector sub-attribute
}

func ParsePatchReq(body io.Reader, rt *schema.ResourceType) (*PatchReq, error) {
	if body == nil {
		return nil, NewBadRequestError("Invalid Patch request data")
	}

	var pr PatchReq
	dec := json.NewDecoder(body)
	err := dec.Decode(&pr)

	if err != nil {
		log.Debugf("Failed to parse the patch request %#v", err)
		return nil, NewBadRequestError(err.Error())
	}

	if len(pr.Operations) == 0 {
		detail := "Invalid patch request, one or more operations must be present"
		log.Debugf(detail)
		return nil, NewBadRequestError(detail)
	}

	for i, po := range pr.Operations {
		po.Op = strings.ToLower(strings.TrimSpace(po.Op))
		po.Path = strings.TrimSpace(po.Path)
		po.Index = i
		pLen := len(po.Path)

		switch po.Op {
		case "add", "replace":
			if po.Value == nil {
				detail := fmt.Sprintf("Invalid patch request, missing value in the %d operation", i)
				log.Debugf(detail)
				return nil, NewBadRequestError(detail)
			}

		case "remove":
			if pLen == 0 {
				detail := fmt.Sprintf("Invalid patch request, missing path in the %d operation", i)
				log.Debugf(detail)
				return nil, NewBadRequestError(detail)
			}

		default:
			detail := fmt.Sprintf("Invalid patch request, unknown operation name %s in %d operation", po.Op, i)
			log.Debugf(detail)
			return nil, NewBadRequestError(detail)
		}

		if pLen > 0 {
			pp, err := parsePath(po.Path, rt)
			if err != nil {
				return nil, err
			}

			po.ParsedPath = pp
		}

	}
	return &pr, nil
}

func parsePath(path string, rt *schema.ResourceType) (pp *ParsedPath, err error) {

	pp = &ParsedPath{}

	runningPath := path
	selector := ""

	defer func() {
		e := recover()
		if e != nil {
			log.Debugf("Failed to parse path %#v", e)
			pp = nil
			err = e.(error)
		}
	}()

	slctrStrtPos := strings.IndexRune(path, '[')

	if slctrStrtPos == 0 {
		detail := fmt.Sprintf("Invalid attribute path %s, missing parent attribute", path)
		return nil, NewBadRequestError(detail)
	}

	if slctrStrtPos > 0 {
		slctrEndPos := strings.LastIndex(path, "]")
		if slctrEndPos == -1 {
			detail := fmt.Sprintf("Invalid attribute path %s, missing ']' character in the path", path)
			return nil, NewBadRequestError(detail)
		}

		selector = strings.ToLower(path[slctrStrtPos+1 : slctrEndPos])

		if len(selector) == 0 {
			detail := fmt.Sprintf("Invalid attribute path, empty selector present", path)
			return nil, NewBadRequestError(detail)
		}

		runningPath = path[:slctrStrtPos]
		slctrEndPos++
		if slctrEndPos < len(path) {
			runningPath += path[slctrEndPos:]
		}
	}

	colonPos := strings.LastIndex(runningPath, ":")

	if colonPos > 0 {
		uri := path[:colonPos]
		if rt.Schema == uri {
			uri = "" // core schema
		} else {
			found := false
			for _, extSc := range rt.SchemaExtensions {
				if uri == extSc.Schema {
					found = true
					break
				}
			}

			if !found {
				detail := fmt.Sprintf("Unknown schema URI %s in the attribute path %s", uri, path)
				return nil, NewBadRequestError(detail)
			}
		}

		pp.Schema = uri

		colonPos++
		if colonPos >= len(path) {
			detail := fmt.Sprintf("Invalid attribute path %s", path)
			return nil, NewBadRequestError(detail)
		}

		runningPath = path[colonPos:]
	}

	dotPos := strings.LastIndex(runningPath, ".")
	if dotPos > colonPos {
		parentName := runningPath[:dotPos]
		dotPos++
		if dotPos >= len(runningPath) {
			detail := fmt.Sprintf("invalid attribute name in the path %s", path)
			return nil, NewBadRequestError(detail)
		}

		pp.ParentType = rt.GetAtType(parentName)
		if pp.ParentType == nil {
			detail := fmt.Sprintf("Unknown complex attribute %s in the path %s", parentName, path)
			return nil, NewBadRequestError(detail)
		}

		atName := runningPath[dotPos:]

		name := parentName + "." + atName
		pp.AtType = rt.GetAtType(name)
		if pp.AtType == nil {
			detail := fmt.Sprintf("Unknown attribute %s in the path %s", name, path)
			return nil, NewBadRequestError(detail)
		}
	} else {
		atName := runningPath
		pp.AtType = rt.GetAtType(atName)
		if pp.AtType == nil {
			detail := fmt.Sprintf("Unknown attribute %s in the path %s", atName, path)
			return nil, NewBadRequestError(detail)
		}
	}

	if len(selector) > 0 {
		slctrName, selector := readSlctrToken(selector)

		if len(slctrName) == 0 {
			detail := fmt.Sprintf("Missing attribute name in the path %s", path)
			return nil, NewBadRequestError(detail)
		}

		selector = strings.TrimSpace(selector) // trim again before reading
		slctrOp := ""
		slctrOp, selector = readSlctrToken(selector)
		slctrOp = strings.TrimSpace(slctrOp)

		if strings.ToLower(slctrOp) != "eq" {
			detail := fmt.Sprintf("Unknown operator name %s in the path %s", slctrOp, path)
			return nil, NewBadRequestError(detail)
		}

		slctrName = strings.ToLower(pp.ParentType.NormName + "." + slctrName)
		pp.SlctrType = rt.GetAtType(slctrName)
		if pp.SlctrType == nil {
			detail := fmt.Sprintf("Unknown selector attribute %s in the path %s", slctrName, path)
			return nil, NewBadRequestError(detail)
		}

		// remaining in the selector is selector's value, trim and store it
		selector = StripQuotes(strings.TrimSpace(selector))
		pp.SlctrVal = CheckValueTypeAndConvert(reflect.ValueOf(selector), pp.SlctrType)
	}

	return pp, nil
}

func readSlctrToken(slctr string) (token string, remSlctr string) {
	spacePos := strings.IndexRune(slctr, ' ')

	if spacePos == -1 {
		return "", slctr
	}

	token = slctr[:spacePos]

	spacePos++

	if spacePos < len(slctr) {
		remSlctr = slctr[spacePos:]
	}

	return token, remSlctr
}
