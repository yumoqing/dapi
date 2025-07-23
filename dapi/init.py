from dapi.dapi import sync_user, bearer_auth, deerer_auth
from ahserver.serverenv import ServerEnv
from rbac.check_perm import register_auth_method

def load_dapi():
	env = ServerEnv()
	env.sync_user = sysnc_user
	register_auth_method('Bearer', bearer_auth)
	register_auth_method('Deerer', deerer_auth)

