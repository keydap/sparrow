package provider

import (
	"sparrow/base"
	"sparrow/conf"
	"sparrow/utils"
)

type PpolicyInterceptor struct {
	Config *conf.Ppolicy
}

func (pi *PpolicyInterceptor) PreCreate(crCtx *base.CreateContext) (err error) {
	inRes := crCtx.InRes
	if inRes.GetType().Name != "User" {
		return nil
	}

	passwordAt := inRes.GetAttr("password")
	if passwordAt != nil {
		vals := passwordAt.GetSimpleAt().Values
		passwdVal := vals[0].(string)
		if !utils.IsPasswordHashed(passwdVal) {
			vals[0] = utils.HashPassword(passwdVal, pi.Config.PasswdHashType)
		}
	}

	acType := inRes.GetType().GetAtType("active")
	activeAt := inRes.GetAttr(acType.NormName)
	if activeAt == nil {
		sa := base.NewSimpleAt(acType, true)
		inRes.AddSimpleAt(sa)
	}

	return err
}

func (pi *PpolicyInterceptor) PostCreate(crCtx *base.CreateContext) {
	// do nothing
}

func (pi *PpolicyInterceptor) PrePatch(patchCtx *base.PatchContext) error {
	if patchCtx.Rt.Name != "User" {
		return nil
	}

	for _, o := range patchCtx.Pr.Operations {
		// only modify user's password attribute do not touch any other password attribute
		if o.ParsedPath.ParentType == nil && o.ParsedPath.AtType.NormName == "password" {
			passwdVal := o.Value.(string)
			if !utils.IsPasswordHashed(passwdVal) {
				o.Value = utils.HashPassword(passwdVal, pi.Config.PasswdHashType)
			}
			break
		}
	}

	return nil
}

func (pi *PpolicyInterceptor) PostPatch(patchedRs *base.Resource, patchCtx *base.PatchContext) {
}
