package base

import ()

type Interceptor interface {
	PreCreate(crCtx *CreateContext) error
	PostCreate(crCtx *CreateContext)

	PrePatch(patchCtx *PatchContext) error
	PostPatch(patchedRs *Resource, patchCtx *PatchContext)
}
