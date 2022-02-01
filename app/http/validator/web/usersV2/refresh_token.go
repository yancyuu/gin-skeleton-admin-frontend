package usersV2

import (
	"goskeleton/app/global/consts"
	"goskeleton/app/http/controller/web/usersV2"
	"goskeleton/app/utils/response"
	"strings"

	"github.com/gin-gonic/gin"
)

type RefreshToken struct {
	Authorization string `json:"token" header:"Authorization" binding:"required,min=20"`
}

// 验证器语法，参见 Register.go文件，有详细说明

func (r RefreshToken) CheckParams(context *gin.Context) {

	//1.基本的验证规则没有通过
	if err := context.ShouldBindHeader(&r); err != nil {
		response.ValidatorError(context, err)
		return
	}
	token := strings.Split(r.Authorization, " ")
	if len(token) == 2 {
		context.Set(consts.ValidatorPrefix+"token", token[1])
		(&usersV2.usersV2{}).RefreshToken(context)
	} else {
		errs := gin.H{
			"tips": "Token不合法，token请放置在header头部分，按照按=>键提交，例如：Authorization：Bearer 你的实际token....",
		}
		response.Fail(context, consts.JwtTokenFormatErrCode, consts.JwtTokenFormatErrMsg, errs)
	}

}