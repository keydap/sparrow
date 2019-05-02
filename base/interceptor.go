package base

import ()

type Interceptor interface {
	PreCreate(crCtx *CreateContext) error
	PostCreate(crCtx *CreateContext)

	PrePatch(patchCtx *PatchContext) error
	PostPatch(patchCtx *PatchContext)

	PreDelete(delCtx *DeleteContext) error
	PostDelete(delCtx *DeleteContext)

	PreReplace(replaceCtx *ReplaceContext) error
	PostReplace(replaceCtx *ReplaceContext)
}
