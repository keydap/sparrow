package base

import (
	"strings"
)

type SsoAttr struct {
	Name                string
	NormName            string
	Format              string // only applicable to SAML attributes
	ScimExpr            string
	atOrFilter          *scimAtOrFilter
	StaticVal           string
	StaticMultiValDelim string
	Value               interface{} // only used when executing SAML attribute's template
}

type scimAtOrFilter struct {
	atName    string
	subAtName string
	filter    *FilterNode
}

func (ssoAt *SsoAttr) GetValueInto(res *Resource, container map[string]interface{}) {
	val := ssoAt.GetValueFrom(res)
	if val != nil {
		container[ssoAt.Name] = val
	}
}

func (ssoAt *SsoAttr) GetValueFrom(res *Resource) interface{} {
	if len(ssoAt.StaticVal) != 0 {
		return ssoAt.StaticVal
	}

	ssoAt.parseAtExpr()
	atName := ssoAt.Name
	subAtName := ""
	if ssoAt.atOrFilter != nil {
		if ssoAt.atOrFilter.filter != nil {
			fltr := ssoAt.atOrFilter.filter
			atType := res.GetType().GetAtType(fltr.Name)
			fltr.SetAtType(atType)
			sa, result := rsCompare(fltr, res)
			if result {
				return sa.Values[0]
			}
		} else {
			atName = ssoAt.atOrFilter.atName
		}
		subAtName = ssoAt.atOrFilter.subAtName
	}

	at := res.GetAttr(atName)
	if at != nil {
		if at.IsSimple() {
			sa := at.GetSimpleAt()
			return sa.Values[0]
		} else {
			log.Warningf("oauth attribute %s evaluated to a complex attribute", atName)
			ca := at.GetComplexAt()
			vals := make([]interface{}, 0)
			if subAtName == "" {
				subAtName = "value"
			}

			for _, atMap := range ca.SubAts {
				if v, ok := atMap[subAtName]; ok {
					vals = append(vals, v.Values[0])
				}
			}

			if len(vals) > 0 {
				return vals
			}
		}
	}

	return nil
}

func (ssoAt *SsoAttr) parseAtExpr() {
	if ssoAt.atOrFilter != nil {
		return
	}

	if len(ssoAt.ScimExpr) == 0 {
		return
	}

	saf := &scimAtOrFilter{}
	if !strings.ContainsRune(ssoAt.ScimExpr, ' ') {
		if strings.ContainsRune(ssoAt.ScimExpr, '.') {
			tokens := strings.SplitN(ssoAt.ScimExpr, ".", 2) // the expression can only contain one '.'
			saf.atName = tokens[0]
			if len(tokens) == 2 {
				saf.subAtName = strings.ToLower(tokens[1])
			}
		} else {
			saf.atName = ssoAt.ScimExpr
		}
		ssoAt.atOrFilter = saf
	} else {
		filter, err := ParseFilter(ssoAt.ScimExpr)
		if err == nil {
			saf.filter = filter
		} else {
			log.Warningf("failed to parse the sso attribute expression %s {%#v}", ssoAt.ScimExpr, err)
			return
		}

		ssoAt.atOrFilter = saf
	}
}
