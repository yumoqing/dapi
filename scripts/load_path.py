"""Generate RBAC permissions for dapi module paths.

Run from Sage root with Sage venv:
    cd ~/repos/sage && ./py3/bin/python ../dapi/scripts/load_path.py
"""
import os
import sys
import asyncio

sage_root = os.environ.get('SAGE_ROOT')
if sage_root and sage_root not in sys.path:
    sys.path.insert(0, sage_root)

from sqlor.dbpools import DBPools
from appPublic.jsonConfig import getConfig
from appPublic.dictObject import DictObject
from appPublic.uniqueID import getID


paths = [
    ("/dapi", "logined"),
    ("/dapi/%", "logined"),
]


async def main():
    config = getConfig('.')
    DBPools(config.databases)
    dbname = 'sage'
    async with DBPools().sqlorContext(dbname) as sor:
        cnt = 0
        for path, role in paths:
            r = await sor.sqlExe(
                'select * from permission where permcode = ${permcode}$',
                {'permcode': path}
            )
            if len(r) == 0:
                await sor.sqlExe(
                    '''insert into permission (id, permcode, permname, permtype)
                       values (${id}$, ${permcode}$, ${permname}$, ${permtype}$)''',
                    {
                        'id': getID(),
                        'permcode': path,
                        'permname': path,
                        'permtype': role,
                    }
                )
                cnt += 1
        print(f'{cnt} path(s) inserted for dapi')


if __name__ == '__main__':
    asyncio.run(main())
