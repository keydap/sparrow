package provider

import (
	"fmt"
	"sparrow/base"
	"sparrow/conf"
	"sparrow/utils"
	"strings"
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
			vals[0] = utils.HashPassword(passwdVal, pi.Config.PasswdHashAlgo)
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

outer:
	for _, o := range patchCtx.Pr.Operations {
		if o.Op == "remove" {
			continue
		}

		// only modify user's password attribute do not touch any other container's password attribute
		if o.ParsedPath == nil || o.ParsedPath.IsExtContainer {
			m := o.Value.(map[string]interface{})
			for k, v := range m {
				if strings.ToLower(k) == "password" {
					passwdVal := fmt.Sprint(v) // do not cast to guard against malicious input e.g an integer was given instead of a string
					if !utils.IsPasswordHashed(passwdVal) {
						passwdVal = utils.HashPassword(passwdVal, pi.Config.PasswdHashAlgo)
						m[k] = passwdVal
					}
					break outer
				}
			}
		} else if o.ParsedPath.ParentType == nil && o.ParsedPath.AtType.NormName == "password" {
			passwdVal := o.Value.(string)
			if !utils.IsPasswordHashed(passwdVal) {
				o.Value = utils.HashPassword(passwdVal, pi.Config.PasswdHashAlgo)
			}
			break
		}
	}

	return nil
}

func (pi *PpolicyInterceptor) PostPatch(patchCtx *base.PatchContext) {
}

func (pi *PpolicyInterceptor) PreDelete(delCtx *base.DeleteContext) error {
	return nil
}

func (pi *PpolicyInterceptor) PostDelete(delCtx *base.DeleteContext) {
}
