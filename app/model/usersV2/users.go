package usersV2

import (
	"goskeleton/app/global/variable"
	"goskeleton/app/model"
	"goskeleton/app/utils/data_bind"
	"goskeleton/app/utils/md5_encrypt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// 创建 userFactory
// 参数说明： 传递空值，默认使用 配置文件选项：UseDbType（mysql）
func CreateUserFactory(sqlType string) *UsersModel {
	return &UsersModel{BaseModel: model.BaseModel{DB: model.UseDbConn(sqlType)}}
}

type UsersModel struct {
	model.BaseModel
	UserName    string `gorm:"column:user_name" json:"user_name"`
	Pass        string `json:"pass"`
	Phone       string `json:"phone"`
	RealName    string `gorm:"column:real_name" json:"real_name"`
	Status      int    `json:"status"`
	Avatar      string `gorm:"column:avatar" json:"avatar"`
	LoginTimes  int    `json:"login_times"`
	Remark      string `json:"remark"`
	LastLoginIp string `gorm:"column:last_login_ip" json:"last_login_ip"`
}

// 表名
func (u *UsersModel) TableName() string {
	return "tb_online_users"
}

// 用户注册（写一个最简单的使用账号、密码注册即可）
func (u *UsersModel) Register(userName, pass, userIp string) bool {
	sql := "INSERT  INTO tb_online_users(user_name,pass,last_login_ip) SELECT ?,?,? FROM DUAL   WHERE NOT EXISTS (SELECT 1  FROM tb_online_users WHERE  user_name=?)"
	result := u.Exec(sql, userName, pass, userIp, userName)
	if result.RowsAffected > 0 {
		return true
	} else {
		return false
	}
}

// 用户登录,
func (u *UsersModel) Login(userName string, pass string) *UsersModel {
	sql := "select id, user_name,real_name,pass,phone  from tb_online_users where  user_name=?  limit 1"
	result := u.Raw(sql, userName).First(u)
	if result.Error == nil {
		// 账号密码验证成功
		if len(u.Pass) > 0 && (u.Pass == md5_encrypt.Base64Md5(pass)) {
			//同时将用户表登陆次数 ++
			sql = "UPDATE  tb_online_users  set login_times=login_times+1  where  id=?"
			if result = u.Exec(sql, u.Id); result.Error == nil {
				return u
			} else {
				variable.ZapLog.Error("用户登录次数++出错:", zap.Error(result.Error))
			}
		}
	} else {
		variable.ZapLog.Error("根据账号查询单条记录出错:", zap.Error(result.Error))
	}
	return nil
}

//记录用户登陆（login）生成的token，每次登陆记录一次token
func (u *UsersModel) OauthLoginToken(userId int64, token string, expiresAt int64, clientIp string) bool {
	sql := "INSERT   INTO  `tb_oauth_access_tokens`(fr_user_id,`action_name`,token,expires_at,client_ip) " +
		"SELECT  ?,'login',? ,?,? FROM DUAL    WHERE   NOT   EXISTS(SELECT  1  FROM  `tb_oauth_access_tokens` a WHERE  a.fr_user_id=?  AND a.action_name='login' AND a.token=?)"
	//注意：token的精确度为秒，如果在一秒之内，一个账号多次调用接口生成的token其实是相同的，这样写入数据库，第二次的影响行数为0，知己实际上操作仍然是有效的。
	//所以这里的判断影响行数>=0 都是正确的，只有 -1 才是执行失败、错误
	return u.Exec(sql, userId, token, time.Unix(expiresAt, 0).Format(variable.DateFormat), clientIp, userId, token).Error == nil
}

//用户刷新token,条件检查: 相关token在过期的时间之内，就符合刷新条件
func (u *UsersModel) OauthRefreshConditionCheck(userId int64, oldToken string) bool {
	// 首先判断旧token在本系统自带的数据库已经存在，才允许继续执行刷新逻辑
	var oldTokenIsExists int
	sql := "SELECT count(*)  as  counts FROM tb_oauth_access_tokens  WHERE fr_user_id =? and token=? and NOW()<DATE_ADD(expires_at,INTERVAL  ? SECOND)"
	return u.Raw(sql, userId, oldToken, variable.ConfigYml.GetInt64("Token.JwtTokenRefreshAllowSec")).First(&oldTokenIsExists).Error == nil && oldTokenIsExists == 1
}

//用户刷新token
func (u *UsersModel) OauthRefreshToken(userId, expiresAt int64, oldToken, newToken, clientIp string) bool {
	sql := "UPDATE   tb_oauth_access_tokens   SET  token=? ,expires_at=?,client_ip=?,updated_at=NOW(),action_name='refresh'  WHERE   fr_user_id=? AND token=?"
	return u.Exec(sql, newToken, time.Unix(expiresAt, 0).Format(variable.DateFormat), clientIp, userId, oldToken).Error == nil
}

//当用户更改密码后，所有的token都失效，必须重新登录
func (u *UsersModel) OauthResetToken(userId int64, newPass, clientIp string) bool {
	//如果用户新旧密码一致，直接返回true，不需要处理
	userItem, err := u.ShowOneItem(userId)
	if userItem != nil && err == nil && userItem.Pass == newPass {
		return true
	} else if userItem != nil {
		maxOnlineUsers := variable.ConfigYml.GetInt("Token.JwtTokenOnlineUsers")
		sql := "UPDATE  tb_oauth_access_tokens  SET  revoked=1,updated_at=NOW(),action_name='ResetPass',client_ip=?  WHERE  fr_user_id=? AND revoked=0 ORDER BY id DESC LIMIT ?  "
		if u.Exec(sql, clientIp, userId, maxOnlineUsers).Error == nil {
			return true
		}
	}
	return false
}

//当tb_online_users 删除数据，相关的token同步删除
func (u *UsersModel) OauthDestroyToken(userId int) bool {
	//如果用户新旧密码一致，直接返回true，不需要处理
	sql := "DELETE FROM  tb_oauth_access_tokens WHERE  fr_user_id=?  "
	//判断>=0, 有些没有登录过的用户没有相关token，此语句执行影响行数为0，但是仍然是执行成功
	return u.Exec(sql, userId).Error == nil
}

// 判断用户token是否在数据库存在+状态OK
func (u *UsersModel) OauthCheckTokenIsOk(userId int64, token string) bool {
	sql := "SELECT   token  FROM  `tb_oauth_access_tokens`  WHERE   fr_user_id=?  AND  revoked=0  AND  expires_at>NOW() ORDER  BY  expires_at  DESC , updated_at  DESC  LIMIT ?"
	maxOnlineUsers := variable.ConfigYml.GetInt("Token.JwtTokenOnlineUsers")
	rows, err := u.Raw(sql, userId, maxOnlineUsers).Rows()
	defer func() {
		//  凡是查询类记得释放记录集
		_ = rows.Close()
	}()

	if err == nil && rows != nil {
		for rows.Next() {
			var tempToken string
			err := rows.Scan(&tempToken)
			if err == nil {
				if tempToken == token {
					return true
				}
			}
		}
	}
	return false
}

// 禁用一个用户的: 1.tb_online_users表的 status 设置为 0，tb_oauth_access_tokens 表的所有token删除
// 禁用一个用户的token请求（本质上就是把tb_online_users表的 status 字段设置为 0 即可）
func (u *UsersModel) SetTokenInvalid(userId int) bool {
	sql := "delete from  `tb_oauth_access_tokens`  where  `fr_user_id`=?  "
	if u.Exec(sql, userId).Error == nil {
		if u.Exec("update  tb_online_users  set  status=0 where   id=?", userId).Error == nil {
			return true
		}
	}
	return false
}

//根据用户ID查询一条信息
func (u *UsersModel) ShowOneItem(userId int64) (*UsersModel, error) {
	sql := "SELECT  `id`, `user_name`,`pass`, `real_name`, `phone`, `avatar`,`status` FROM  `tb_online_users`  WHERE `status`=1 and   id=? LIMIT 1"
	result := u.Raw(sql, userId).First(u)
	if result.Error == nil {
		return u, nil
	} else {
		return nil, result.Error
	}
}

// 根据关键词查询用户表的条数
func (u *UsersModel) getCounts(userName string) (counts int64) {
	sql := "select  count(*) as counts from tb_online_users WHERE  ( user_name like ? or real_name like  ?) "
	if _ = u.Raw(sql, "%"+userName+"%", "%"+userName+"%").First(&counts); counts > 0 {
		return counts
	} else {
		return 0
	}
}

// 查询（根据关键词模糊查询）
func (u *UsersModel) List(userName string, limitStart, limitItems int) (totalCounts int64, list []UsersModel) {
	totalCounts = u.getCounts(userName)
	if totalCounts > 0 {
		sql := `
			SELECT  a.id, a.user_name, a.real_name,a.avatar, a.phone, a.status,a.last_login_ip,a.remark,a.login_times,
			DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s')  AS created_at,	DATE_FORMAT(updated_at,'%Y-%m-%d %H:%i:%s')  AS updated_at  
			 FROM  tb_online_users a WHERE  ( user_name LIKE ? OR real_name LIKE  ?) LIMIT ?,?
			`
		if res := u.Raw(sql, "%"+userName+"%", "%"+userName+"%", limitStart, limitItems).Find(&list); res.RowsAffected > 0 {
			return totalCounts, list
		} else {
			return totalCounts, nil
		}
	}
	return 0, nil
}

//新增
func (u *UsersModel) InsertData(c *gin.Context) bool {
	var tmp UsersModel
	if err := data_bind.ShouldBindFormDataToModel(c, &tmp); err == nil {
		tmp.Pass = md5_encrypt.Base64Md5(tmp.Pass)
		tmp.LastLoginIp = c.ClientIP()
		// 用户名不能重复
		var counts int64
		u.Model(u).Where("user_name=?", tmp.UserName).Count(&counts)
		if counts == 0 {
			if res := u.Create(&tmp); res.Error == nil {
				return true
			} else {
				variable.ZapLog.Error("UsersModel 数据新增出错", zap.Error(res.Error))
			}
		} else {
			variable.ZapLog.Info("UsersModel 数据新增失败，用户名已经存在：" + tmp.UserName)
		}

	} else {
		variable.ZapLog.Error("UsersModel 数据绑定出错", zap.Error(err))
	}
	return false
}

//更新
func (u *UsersModel) UpdateData(c *gin.Context) bool {
	var tmp UsersModel
	if err := data_bind.ShouldBindFormDataToModel(c, &tmp); err == nil {
		if strings.Trim(tmp.Pass, " ") == "####*****####" {
			// 系统默认虚拟密码，不对真实业务做任何处理
			tmp.Pass = ""
		} else {
			tmp.Pass = md5_encrypt.Base64Md5(tmp.Pass)
			tmp.LastLoginIp = c.ClientIP()
		}
		// updates 不会处理零值字段，save 会全量覆盖式更新字段
		// omit 忽略指定字段
		if len(tmp.Pass) > 0 {
			if u.OauthResetToken(tmp.Id, tmp.Pass, tmp.LastLoginIp) {
				if res := u.Omit("CreatedAt").Save(&tmp); res.Error == nil {
					return true
				} else {
					variable.ZapLog.Error("UsersModel 数据更更新出错", zap.Error(res.Error))
				}
			}
		} else {
			if res := u.Omit("CreatedAt", "Pass").Save(&tmp); res.Error == nil {
				return true
			} else {
				variable.ZapLog.Error("UsersModel 数据更更新出错", zap.Error(res.Error))
			}
		}
	}
	return false
}
