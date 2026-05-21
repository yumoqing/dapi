from traceback import format_exc
from appPublic.log import debug, exception, info
from appPublic.timeUtils import curDateString
from appPublic.aes import aes_decode_b64, aes_encode_b64
from appPublic.uniqueID import getID
from time import time
from sqlor.dbpools import get_sor_context
from ahserver.serverenv import get_serverenv, ServerEnv
from ahserver.auth_api import get_session_userinfo, user_login
from sqlor.dbpools import DBPools
from rbac.check_perm import create_org, create_user


return_messages = {
	-9: '用户同步：未知未知错误',
	-4: '用户同步：添加用户apikey失败',
	-3: '用户同步：添加用户失败',
	-2: '用户同步：添加机构失败',
	-1: '用户同步：用户已同步'
}

def get_dbname():
	dbname = get_serverenv('get_module_dbname')('dapi')
	return dbname

async def get_secretkey(sor, appid):
	recs = await sor.R('downapp', {'id':appid})
	if len(recs) < 1:
		return None
	secretkey = recs[0].secretkey
	f = get_serverenv('password_decode')
	return f(secretkey)

async def get_apikey_user(sor, apikey, client_ip):
	f = get_serverenv('password_encode')
	apikey = f(apikey)
	debug(f'{apikey=}')
	sql = """select u.*, a.dappid, b.allowedips from downapikey a, users u, downapp b
where a.userid = u.id 
	and b.id = a.dappid
	and a.apikey=${apikey}$ 
	and a.expired_date > ${today}$"""

	recs = await sor.sqlExe(sql, {"apikey":apikey, 'today': curDateString()})
	if len(recs) < 1:
		debug(f'{apikey=} not registered')
		return None
	rec = recs[0]
	if rec.allowedips is None or rec.allowedips == '':
		return rec

	ips = rec.allowedips.split(',')
	ips = [ ip.strip() for ip in ips ]
	if client_ip not in ips:
		debug(f' {client_ip} not in {rec.allowedips=}')
		return None
	return rec

async def bearer_auth(sor, request):
	auth = request.headers.get('Authorization')
	if auth is None:
		debug(f'headers has not "Authorization"')
		return None
	if not auth.startswith('Bearer '):
		debug(f'"Authorization" not starts with "Bearer "')
		return None
	apikey = auth[7:]
	client_ip = request['client_ip']
	return await apikey_user(sor, apikey, client_ip, request)

async def apikey_user(sor, apikey, client_ip, request):
	if apikey is None:
		debug(f'keykey is None')
		return None
	user = await get_apikey_user(sor, apikey, client_ip)
	if user is None:
		debug(f'get_apikey_user() {apikey=}, {client_ip} return None')
		return None
	await user_login(request, user.id, username=user.username, userorgid=user.orgid)
	
	# 认证成功后，给用户添加downappuser角色（角色id=downapp.id）
	dappid = getattr(user, 'dappid', None)
	if dappid:
		await ensure_downappuser_role_and_assign(sor, user.id, dappid)
	
	return user.id

async def ensure_downappuser_role_and_assign(sor, userid, dappid):
	"""确保downapp/logined角色存在，并分配给用户"""
	try:
		# 检查角色是否存在，不存在则创建
		roles = await sor.R('role', {'orgtypeid': 'downapp', 'name': 'logined'})
		if not roles:
			roleid = getID()
			await sor.C('role', {
				'id': roleid,
				'name': 'logined',
				'orgtypeid': 'downapp'
			})
			debug(f'created logined role (downapp): {roleid}')
		else:
			roleid = roles[0].id
		
		# 检查用户是否已有该角色
		existing = await sor.R('userrole', {'userid': userid, 'roleid': roleid})
		if not existing:
			await sor.C('userrole', {
				'id': getID(),
				'userid': userid,
				'roleid': roleid
			})
			debug(f'assigned logined role {roleid} (downapp) to user {userid}')
	except Exception as e:
		exception(f'ensure_downappuser_role_and_assign error: {e}')

async def x_api_key_auth(sor, request):
	"""Anthropic标准认证模式：从 x-api-key header 读取apikey"""
	apikey = request.headers.get('x-api-key')
	if apikey is None:
		debug(f'x-api-key header not found')
		return None
	client_ip = request['client_ip']
	return await apikey_user(sor, apikey, client_ip, request)

async def deerer_auth(sor, request):
	auth = request.headers.get('Authorization')
	if auth is None:
		return None
	if not auth.startswith('Deerer '):
		return None
	deer_data = auth[7:]
	client_ip = request['client_ip']
	return await deerer_user(sor, deer_data, client_ip, request)

async def get_user_dapp_apikey(dappid, userid):
	"""
	获得用户在downapp的apikey
	"""
	sql = """select b.* from downapp a, downapikey b where a.id=b.dappid and a.id=${dappid}$"""
	env = ServerEnv()
	async with get_sor_context(env, 'dapi') as sor:
		recs = await sor.sqlExe(sql, {'dappid': dappid})
		if not recs:
			debug(f'{dappid=}, {userid=} not exist is downapikey')
			return None
		apikey = env.password_decode(recs[0].apikey)
		return apikey
	return None

def deerer_header(appid, sk, apikey):
	tim = time.time()
	txt = f'{tim}:{apikey}' 
	cyber = aes_encode_b64(sk, txt)
	return f'Deerer {appid}-:-{cyber}'

def deerer_apikey(sk, cyber):
	txt = aes_decode_b64(sk, cyber)
	t, apikey = txt.split(':')
	return apikey

async def deerer_user(sor, deer_data, client_ip, request):
	appid, cyber = deer_data.split('-:-')
	secretkey = await get_secretkey(sor, appid)
	try:
		txt = aes_decode_b64(secretkey, cyber)
		t, apikey = txt.split(':')
		return await apikey_user(sor, apikey, client_ip, request)
	except Exception as e:
		exception(f'{e}, {deer_data=},{secretkey=}')
		return None
			
def return_error(code):
	return {
		'status':'error',
		'errcode': code,
		'errmsg': return_messages.get(code, '未定义信息')
	}

def return_success(data):
	return {
		'status':'success',
		'data':data
	}

async def get_orgid_by_dorgid(sor, dappid, dorgid):
	"""检查外部机构ID(dorgid)在本系统中是否已存在。
	
	dorgid 即为本系统 orgid，直接检查 organization 表。
	"""
	recs = await sor.R('organization', {'id': dorgid})
	if len(recs) < 1:
		return None
	return dorgid

async def check_duserid_exists(sor, dappid, duserid):
	"""检查用户(dappid+duserid)是否已存在apikey"""
	d = {
		'dappid': dappid,
		'userid': duserid,
	}
	recs = await sor.R('downapikey', d)
	if len(recs):
		return True
	return False

async def add_organzation(sor, dappid, org):
	id = getID()
	org['id'] = id
	await create_org(sor, org)
	return id

async def add_user(sor, user):
	id = getID()
	user['id'] = id
	await create_user(sor, user, roles=user.get('roles'))
	return id
	
async def add_apikey(sor, dappid, userid):
	"""为用户创建apikey。
	
	downapikey表字段: id, dappid, userid, apikey, enabled_date, expired_date
	duserid = 本系统 userid，直接存入 userid 字段。
	"""
	apikey = getID()
	d = {
		'id': getID(),
		'dappid': dappid, 
		'userid': userid,
		'apikey': apikey,
		'enabled_date': curDateString(),
		'expired_date': '9999-12-31'
	}
	await sor.C('downapikey', d)
	return apikey

async def create_user_apikey(sor, dappid, user_id, user_orgid, **kwargs):
	"""为已有用户创建dapi apikey
	
	Args:
		sor: sqlor连接对象
		dappid: dapi应用ID
		user_id: rbac用户ID
		user_orgid: 用户机构ID
		**kwargs: 可选字段（username, name, email等users表字段）
	
	Returns:
		dict: {'status': 'success'|'error', 'apikey': str, 'message': str}
	"""
	try:
		# downapikey表实际字段: id, dappid, userid, apikey, enabled_date, expired_date
		# 按(dappid, userid)唯一性查询
		existing = await sor.R('downapikey', {
			'dappid': dappid,
			'userid': user_id,
		})
		
		if existing:
			# 返回现有apikey
			f = get_serverenv('password_decode')
			apikey = f(existing[0].apikey)
			return {
				'status': 'success',
				'apikey': apikey,
				'user_id': user_id,
				'message': '用户apikey已存在'
			}
		
		# 创建新apikey
		apikey_value = getID()
		ns = {
			'id': getID(),
			'dappid': dappid,
			'userid': user_id,
			'apikey': password_encode(apikey_value),
			'enabled_date': curDateString(),
			'expired_date': '9999-12-31'
		}
		
		await sor.C('downapikey', ns)
		
		return {
			'status': 'success',
			'apikey': apikey_value,
			'user_id': user_id,
			'message': 'apikey创建成功'
		}
	except Exception as e:
		exception(f'create_user_apikey error: {e}')
		return {
			'status': 'error',
			'message': f'创建apikey失败: {str(e)}'
		}

async def sync_user(request, params_kw, *args, **kw):
	dappid = params_kw.dappid
	db = DBPools()
	dbname = get_dbname()
	userinfo = await get_session_userinfo(request)
	async with db.sqlorContext(dbname) as sor:
		ret_users = []
		roles = [{
			'orgtypeid': 'customer',
			'roles': [ 'customer', 'syncuser' ]
		}]
		for o in  params_kw.organizations:
			for u in o['users']:
				dorgid = o['id']
				duserid = u['id']
				orgid = await get_orgid_by_dorgid(sor, dappid, dorgid)
				if orgid is None:
					if o.get('parentid') is None:
						o['parentid'] = userinfo.userorgid
					else:
						nparentid = await get_orgid_by_dorgid(sor, dappid, o.get('parentid'))
						o['parentid'] = nparentid
					orgid = await add_organzation(sor, dappid, o)
					if orgid is None:
						return return_error(-2)
				u['orgid'] = o['id']
				u['roles'] = roles
				exists = check_duserid_exists(sor, dappid, duserid)
				if exists:
					return return_error(-1)
				userid = await add_user(sor, u)
				if userid is None:
					return return_error(-3)
				apikey = await add_apikey(sor, dappid, userid)
				if apikey is None:
					return return_error(-4)
				ret_users.append({
					'id': u['id'],
					'apikey': apikey
				})
		return return_success(ret_users)
	return return_error(-9)

if __name__ == '__main__':
	print('ggg')
