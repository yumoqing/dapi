from daap.dapi import dearer_header, manis_header
from ahserver.serverenv import ServerEnv

def load_dapi():
	env = ServerEnv
	env.dearer_header = dearer_header
	env.manis_header = manis_header
