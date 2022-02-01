/*
 * @Descripttion:
 * @version:
 * @Author: yancyyu
 * @Date: 2022-02-02 00:21:01
 * @LastEditors: yancyyu
 * @LastEditTime: 2022-02-02 00:36:06
 */
package usersV2

import (
	"goskeleton/app/global/consts"
	"goskeleton/app/http/controller/web/usersV2"
	"goskeleton/app/http/validator/core/data_transfer"
	"goskeleton/app/utils/response"

	"github.com/gin-gonic/gin"
)

type Edit struct {
	BaseField
	Id
}

// 验证器语法，参见 Register.go文件，有详细说明

func (u Edit) CheckParams(context *gin.Context) {
	//1.基本的验证规则没有通过
	if err := context.ShouldBind(&u); err != nil {
		response.ValidatorError(context, err)
		return
	}

	//  该函数主要是将本结构体的字段（成员）按照 consts.ValidatorPrefix+ json标签对应的 键 => 值 形式直接传递给下一步（控制器）
	extraAddBindDataContext := data_transfer.DataAddContext(u, consts.ValidatorPrefix, context)
	if extraAddBindDataContext == nil {
		response.ErrorSystem(context, "UserUpdate表单验证器json化失败", "")
	} else {
		// 验证完成，调用控制器,并将验证器成员(字段)递给控制器，保持上下文数据一致性
		(&usersV2.usersV2{}).Edit(extraAddBindDataContext)
	}
}