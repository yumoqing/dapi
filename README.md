# dapi（kyapikeyclient）— 下位系统 API Key 客户端模块

给「下位系统」（downapp，即接入本平台的下游应用）发放/校验 API Key，并向 rbac
注册两种自定义 HTTP 认证方法（`Bearer`、`Deerer`），使外部系统能凭 apikey 调用平台端点。

## 数据表（models/*.json）

| 表 | 说明 | 关键字段 |
|---|------|---------|
| downapp | 下位系统注册 | id, name, description, secretkey（AES 加密存储）, allowedips（IP 白名单）, orgid |
| downapikey | 下位系统 apikey | id, dappid（→downapp）, userid（→users）, apikey（加密存储）, enabled_date, expired_date |

CRUD 定义在 `json/`（downapp/downapikey），页面由宿主 build.sh xls2ui 生成。

## 认证方式（经 rbac.check_perm.register_auth_method 注册）

- `Bearer <apikey>` → `bearer_auth(sor, request)`：标准 apikey 认证
- `Deerer <数据>` → `deerer_auth(sor, request)`：下位系统专用签名认证
- 另有 `x_api_key_auth(sor, request)`：X-Api-Key 头认证（env 暴露，未注册为 auth method）

认证链：apikey 先经 `password_encode` 加密后与库比对（明文不落库）；
`get_apikey_user` 联查 downapikey/users/downapp，同时校验 allowedips 与有效期。

## 注册到 ServerEnv（load_dapi，dapi/init.py）

`sync_user`、`deerer_user`、`apikey_user`、`create_user_apikey`、`x_api_key_auth`、
`get_user_dapp_apikey(dappid, userid)`。

`sync_user(request, params_kw, ...)`：下位系统用户同步（建机构 create_org → 建用户
create_user → 发 apikey create_user_apikey），错误码见 dapi.py return_messages
（-1 已同步 / -2 加机构失败 / -3 加用户失败 / -4 加 apikey 失败 / -9 未知错误）。

## 前端端点（wwwroot/，全部 logined 级）

apikey_manage.ui（管理页）、apply/create/update/delete/copy/get_apikey.dspy、
do_update_apikey.dspy、downapps.dspy、deerer_user.dspy、jumpin.dspy（下位系统跳入登录）。

## RBAC 权限注册

`scripts/load_path.py`：从 Sage 根目录用宿主 venv 跑，把上述 17 个路径按 `logined`
授权写入 permission/rolepermission（新增 dspy 必须同步加进 paths 列表，否则 403）。

## 宿主集成

- build.sh 基础包清单成员：clone + `pip install pkgs/dapi/`
- 宿主 `init()` 里调用 `load_dapi()`（依赖 rbac 的 register_auth_method，装载顺序在 rbac 之后）
- 密钥存储依赖宿主 password_key（AES），与 Sage 宿主同步（build.sh 第 9 步）

## 部署注意

- secretkey/apikey 均为 AES 密文，跨环境迁移数据必须连同 password_key 一起迁
- downapp.allowedips 为空 = 不限制来源 IP；生产建议配置白名单
- 代码里的 `"Bearer "`/`"Deerer "` 前缀字面量注意：某些安全扫描会把源码中的 Bearer 字面量替换掉，改动 init.py 时先 grep 确认注册前缀完整
