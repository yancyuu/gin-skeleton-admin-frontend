###    GinSkeleton-Admin (后端部分)
![预览图](https://www.ginskeleton.com/images/home_page1.png)

### [在线演示地址: GinSkeleton-Admin](http://139.196.101.31:20202/)  

### 系统说明  
>   1.本部分为后端接口部分,基于 GinSkeleton(v1.5.10) 开发.  
>   2.前端界面部分,基于 Iview(v4.5.0)开发, [界面系统仓库地址](https://gitee.com/daitougege/gin-skeleton-admin-frontend) .  
>   3.本系统已经集成的功能模块是一个企业级系统必备的基础、通用功能模块，请勿删除.        
>   4.如发现基础功能有问题，请及时向官方反馈，提交 Issue | PR，由官方统一更新、升级, 基础模块前后端已经做了目录分类,后续可直接更新相关文件夹.       
>   5.Admin 系统只支持 mysql（5.x-8.x 测试100% 通过）, 其他数据库目前暂未适配.  
>   6.admin 系统后台菜单目前只支持 2 级,暂不支持 3 级，主要是因为权限模块做树形化权限继承、对接 Casbin 同样以树形继承关系对接,存在比较复杂的逻辑，如果菜单层级太多，当底层节点的上下级关系变化太大时，会产生更加复杂的权限继承关系重新设置,最终会导致系统基础功能不稳定，3 级树形菜单将在下一个大版本增加，短期不会有 3 级菜单.    


###  前言
> 1.使用本系统之前请了解GinSkeleton 主线版本的主要功能, [主线版本仓库地址](https://gitee.com/daitougege/GinSkeleton) .


### Admin系统已经集成的基础功能模块介绍

#### 1.系统菜单：  
> 1.1 后台设置的菜单+绑定的按钮(例如：增、删、改、查), 凡是没有设置为禁用状态，都对应前端的一个视图(页面地址)+界面按钮.  
> 1.2 `系统菜单` 可以在 `权限分配` 多次分配给组织机构(公司、部门、岗位)节点,凡是挂接在特定岗位底下的用户，都会继承已分配的视图+按钮元素.   
> 1.3 `系统菜单` 新增界面默认会有四个按钮,分别是 增、删、改、查, 每个按钮都对应一个地址，当该菜单被分配给组织机构节点时,按钮对应的地址会自动绑定到 `casbin` 模块对应的表,如果一开始菜单没有设置正确相关按钮、接口地址，青虫修改按钮对应的地址，重新分配权限即可.  
![菜单与前端页面](https://www.ginskeleton.com/images/menu_page.png)  

#### 2.用户管理：
> 管理用户账号、登录 `token` 认证。

#### 3.组织机构： 
>  企业以集团、分公司、部门、岗位等，按照层级划分(树形划分),所形成的垂直管理体系.   
#### 4.岗位成员： 
> 用于将用户配置在组织机构树设置的岗位, 使用户与组织机构建立关联关系, 在 `权限分配` 菜单为特定组织机构分配权限后，该用户则自动垂直继承权限.  

#### 5.权限分配： 
>  权限可以分配给岗位、也可以分配给部门、甚至可以分配给公司,岗位会继承他的上一级部门的权限，部门会继续继承他的上一级公司的权限，而同一个岗位底下的用户则拥有该岗位以及继承后的所有权限.  
![权限继承关系](https://www.ginskeleton.com/images/auth_extends.png)  
> 本系统超级管理员所在岗位：  
![超级管理员](https://www.ginskeleton.com/images/auth_admin.jpg)

#### 6.权限分析：
>  由于我们以继承方式做权限的分配与管控，那么当用户的权限来源比较多的时候，无法很快定位权限来源, 此时你可以通过权限分析来定位它的来源.

#### 7.按钮设置：
> 每一个按钮都一个名称和英文代码,按钮的英文代码是后端统一规定，前端开发时向后端获取,后端才能精准控制按钮权限.
> 此外，每个按钮点击时都对应一下接口的请求,本质上前端的按钮 ≈ 后台的接口

### 运行 Admin 系统接口服务    
```code  

//1.还原数据库：
    //1.1 请将备份文件复制到桌面，相关路径：./database/db_ginskeleton.7z, 请解压后使用 sqlyog 等 mysql 客户端进行快速还原.  
    //1.2 如果需要修改数据库名称,打开以上文件开头部自行修改数据库名称即可.    

//2.ginskeleton-admin 项目配置文件 config/gorm_v2.yml 配置数据库账号、密码、端口等：

//3.使用 goland 打开本项目， cmd/web/main.go 文件通过鼠标右键 运行，或者 main 函数处显示的箭头启动即可

```

### 业务模块开发指南
> 1.我们通过1个实例带大家了解一个最基本的模块是如何进行开发、前后端对接起来的.  
> 2.[业务开发指南](./docs/guide.md)  

### 版本更新日志

#### V1.0.11 (2021-05-15)
> 1.修复数据查询时间格式化书写错误的bug,mysql日期时间格式化由 %Y-%m-%d %h:%i:%s 修复为 ：%Y-%m-%d %H:%i:%s ，由于 %h 小写导致了时间比实际滞后8小时.  

#### V1.0.10 (2021-04-02)
> 1.系统菜单主表与子表数据接受方式以及后续的总体逻辑更新.  

#### V1.0.01 (2021-03-27)  
> Bug修复:  
> 1.系统菜单添加按钮失败的错误.  
1.1 涉及到的文件：app/model/auth/auth_system_menu_button.go  
1.2 app/service/auth_system_menu/auth_organization_post_service.go  
2.快速升级、更新的办法：可直接使用官方仓库最新代码覆盖自带代码即可.  

####    V1.0.00 (2021-03-20)
> 1.GinSkeleton-Admin 系统 v1.0.0 版本发布. 

