import mariadb
import sys
import bcrypt

try:
    conn = mariadb.connect(
        user = "root",
        password = "0000",
        host = "127.0.0.1",
        port = 3306,
        database = "smilegate_auth",
    )

except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

cur = conn.cursor()
cur.execute(f'SELECT password FROM auth.password')
conn.commit()
rows = cur.fetchall()
print(rows[0][0])

userPW = 'tests'
userPWencoded = userPW.encode('utf-8')

"""
해당 로그인 요청의 ID와 PW가 DB에 존재하는지, 일치하는지 확인
"""
print(userPW.encode('utf-8'))
print(bcrypt.checkpw(userPW.encode('utf-8'), rows[0][0].encode('utf-8')))

cur.close()
conn.close()