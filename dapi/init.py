from dapi.dapi import get_user_dapp_apikey, sync_user, bearer_auth, deerer_auth, deerer_user, apikey_user, create_user_apikey, x_api_key_auth
from ahserver.serverenv import ServerEnv
from rbac.check_perm import register_auth_method

def load_dapi():
	env = ServerEnv()
	env.sync_user = sync_user
	env.deerer_user = deerer_user
	env.apikey_user = apikey_user
	env.create_user_apikey = create_user_apikey
	env.x_api_key_auth = x_api_key_auth
	env.get_user_dapp_apikey = get_user_dapp_apikey
	register_auth_method('Bearer ', bearer_auth)
	register_auth_method('Deerer ', deerer_auth)

