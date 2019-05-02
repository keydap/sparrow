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

func (ri *RemoveNeverAttrInterceptor) PostPatch(patchCtx *base.PatchContext) {
	removeNeverAttrs(patchCtx.Res)
}

func removeNeverAttrs(rs *base.Resource) {
	for atPath, _ := range rs.GetType().AtsNeverRtn {
		rs.DeleteAttr(atPath)
	}
}

func (ri *RemoveNeverAttrInterceptor) PreDelete(delCtx *base.DeleteContext) error {
	return nil
}

func (ri *RemoveNeverAttrInterceptor) PostDelete(delCtx *base.DeleteContext) {
}

func (ri *RemoveNeverAttrInterceptor) PreReplace(replaceCtx *base.ReplaceContext) error {
	return nil
}

func (ri *RemoveNeverAttrInterceptor) PostReplace(replaceCtx *base.ReplaceContext) {
}
