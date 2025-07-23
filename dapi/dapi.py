
from time import time
from appPublic.aes import aes_encrypt_ecb, aes_decrypt_ecb
from appPublic.timeUtils import curDateString
from sqlor.dbpools import DBPools
from ahserver.serverenv import get_serverenv
from ahserver.auth_api import get_session_userinfo

def get_dbname():
	f = get_serverenv('get_module_dbname')
	if f:
		return f('dapi')
	return None

def build_manisdata(appid, apikey, secretkey):
	"""
	this appid is isusses by upapp we connect to,
	secretkey is with the appid, is s fixed key from upapp
	apikey is user's apikey assigned by upapp when the users is synchronous to upapp
	"""
	t = time()
	txt = f'{t}:{apikey}
	cyber = aes_encrypt_ecb(secretkey, txt)
	return f'Manis {appid}-:-{cyber}'
	
def build_dearerdata(apikey):
	return f'Dearer {apikey}'

async def get_apikeys(sor, appid, orgid, userid):
	ns = {
		'appid':appid,
		'orgid':orgid,
		'userid':userid,
		'today':curDateString()
	}
	sql = """select a.myid, b.apikey, b.secretkey from upapp a, upapikey b
where a.upappid = ${appid}$
	and b.userid = ${userid}$
	and b.orgid = ${orgid}$
	and b.expired_date > ${today}$
	and b.enabled_date <= ${today}$"""
	recs = await sor.sqlExe(sql, ns)
	if len(recs) > 0:
		r = recs[0]
		return r
	return r

async def sync_users(request, upappid, orgid):
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		upapp = await get_upapp(sor, upappid)

async def dearer_header(request, appid):
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		u = await get_session_userinfo(request)
		r  = await get_apikeys(sor, appid, u.userorgid, u.userid)
		if r is None:
			return None
		dearer = build_dearerdata(r.apikey)
		return {
			"Authorization": dearer
		}
	return {}
	
async def manis_header(request, appid):
	db = DBPools()
	dbname = get_dbname()
	async with db.sqlorContext(dbname) as sor:
		u = await get_session_userinfo(request)
		r  = await get_apikeys(sor, appid, u.userorgid, u.userid)
		if r is None:
			return None
		manis = build_manisdata(r.myid, r.apikey, r.secretkey)
		return {
			"Authorization": manis
		}
	return {}

