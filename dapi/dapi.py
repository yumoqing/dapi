from traceback import format_exc
from appPublic.log import debug, exception, info
from appPublic.timeUtils import curDateString
from appPublic.aes import aes_encrypt_ecb, aes_decrypt_ecb
from appPublic.uniqueID import getID
from time import time
from ahserver.serverenv import ServerEnv
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
	return f(secret_key).encode('utf-8')

async def get_apikey_user(sor, apikey, client_ip):
	f = get_serverenv('password_encode')
	apikey = f(apikey)
	sql = """select u.*, b.allowedips from downapikey a, users u, downapp b
where a.userid = b.id 
	and b.id = a.dappid
	and apikey=${apikey}$ 
	and expired_date > ${today}$"""

	recs = await sor.sqlExe(sql, {"apikey":apikey, 'today': curDateString()})
	if len(recs) < 1:
		debug(f'{apikey=} not registered')
		return None
	ips = rec[i].allowedips.split(',')
	ips = [ ip.strip() for ip in ips ]
	if client_ip not in ips:
		debug(f' {client_ip} not in {ips=}')
		return None
	return recs[0]

async def bearer_auth(request):
	auth = request.headers.get('Authorization')
	if auth is None:
		return None
	if not auth.startswith('Bearer '):
		return None
	apikey = auth[7:]
	client_ip = request['client_ip']
	if apikey is None:
		return None
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		user = await get_apikey_user(sor, apikey, client_ip)
		await user_login(user.id, username=user.username, userorgid=user.orgid)
		return user.id
	return None

async def deerer_auth(request):
	auth = request.headers.get('Authorization')
	if auth is None:
		return None
	if not auth.startswith('Deerer '):
		return None
	client_ip = request['client_ip']
	deer_data = auth[7:]
	appid, cyber = bear_data.split('-:-')
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		secretkey = await get_secretkey(sor, appid)
		txt = aes_decrypt_ecb(secretkey, cyber)
		t, apikey = txt.split(':')
		user = await get_apikey_user(sor, apikey, client_ip)
		await user_login(user.id, username=user.username, userorgid=user.orgid)
		return user.id
	
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
	d = {
		'dappid':dappid,
		'dorgid':dorgid
	}
	recs = await sor.R('downapikey', d)
	if len(recs) < 1:
		return None
	return recs[0].orgid

async def check_duserid_exists(sor, dappid, dorgid, duserid):
	d = {
		'dappid': dappid,
		'duserid': duserid,
		'dorgid': dorgid
	}
	recs = await sor.R('kwdownapikey', d)
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
	
async def add_apikey(sor, dappid, dorgid, duserid, orgid, userid):
	apikey = getID()
	d = {
		'id': getID,
		'dappid': dappid, 
		'dorgid': dorgid,
		'duserid': duserid,
		'orgid': orgid,
		'userid': userid,
		'apikey': id,
		'enabled': '1',
		'created_at': curDateString(),
		'expires_at': '9999-12-31'
	}
	await sor.C('downapikey', d)
	return apikey

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
				exists = check_duserid_exists(sor, dappid, dorgid, duserid)
				if exists:
					return return_error(-1)
				userid = await add_user(sor, u)
				if userid is None:
					return return_error(-3)
				apikey = await add_apikey(sor, dappid, orgid, userid, u)
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
