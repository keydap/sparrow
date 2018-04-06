package provider

import (
	"sparrow/base"
)

// Removes the attibutes that should never be returned after creating a resource
type RemoveNeverAttrInterceptor struct {
}

func (ri *RemoveNeverAttrInterceptor) PreCreate(crCtx *base.CreateContext) error {
	// do nothing
	return nil
}

func (ri *RemoveNeverAttrInterceptor) PostCreate(crCtx *base.CreateContext) {
	removeNeverAttrs(crCtx.InRes)
}

func (ri *RemoveNeverAttrInterceptor) PrePatch(patchCtx *base.PatchContext) error {
	return nil
}

func (ri *RemoveNeverAttrInterceptor) PostPatch(patchedRs *base.Resource, patchCtx *base.PatchContext) {
	removeNeverAttrs(patchedRs)
}

func removeNeverAttrs(rs *base.Resource) {
	for atPath, _ := range rs.GetType().AtsNeverRtn {
		rs.DeleteAttr(atPath)
	}
}
