import sys
sys.path.append('/app')
from config.database import get_db_connection

conn = get_db_connection()
c = conn.cursor()
mock_hex = """[DDoS] SYN flood
0000   00 50 56 c0 00 01 00 50 56 c0 00 02 08 00 45 00  .PV....PV.....E.
0010   00 3c 12 34 40 00 40 06 a1 b2 0a 00 00 37 c0 a8  .<.4@.@......7..
0020   0d 81 c0 12 00 50 11 22 33 44 00 00 00 00 70 02  .....P."3D....p.
0030   20 00 3b 4a 00 00 02 04 05 b4 04 02 08 0a 00 11   .;J............
0040   22 33 00 00 00 00 01 03 03 07                    "3........"""

c.execute("UPDATE ids_dulieu SET sample_hex = %s WHERE top_ip = '10.0.0.55'", (mock_hex,))
conn.commit()
print(f'Rows updated: {c.rowcount}')
