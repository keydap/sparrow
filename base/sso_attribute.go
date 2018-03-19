package base

import (
	"strings"
)

type SsoAttr struct {
	Name                string
	ScimExpr            string
	atOrFilter          *scimAtOrFilter
	StaticVal           string
	StaticMultiValDelim string
}

type scimAtOrFilter struct {
	atName string
	filter *FilterNode
}

func (ssoAt *SsoAttr) GetValueFrom(res *Resource, container map[string]interface{}) {
	if len(ssoAt.StaticVal) != 0 {
		container[ssoAt.Name] = ssoAt.StaticVal
		return
	}

	ssoAt.parseAtExpr()
	atName := ssoAt.Name
	if ssoAt.atOrFilter != nil {
		if ssoAt.atOrFilter.filter != nil {
			sa, result := rsCompare(ssoAt.atOrFilter.filter, res)
			if result {
				container[ssoAt.Name] = sa.Values[0]
				return
			}
		} else {
			atName = ssoAt.atOrFilter.atName
		}
	}

	at := res.GetAttr(atName)
	if at != nil {
		if at.IsSimple() {
			sa := at.GetSimpleAt()
			container[ssoAt.Name] = sa.Values[0]
		} else {
			//ca := at.GetComplexAt()
			//subAt := ca.GetFirstSubAt()
			log.Warningf("oauth attribute %s evaluated to a complex attribute, ignoring", atName)
		}
	}
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
		saf.atName = ssoAt.ScimExpr
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
