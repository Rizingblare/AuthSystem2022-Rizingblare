from flask import Flask
from flask import request
from flask import render_template
from flask import jsonify
from flask import make_response


# 로그인 유저 인증 토큰 생성
import jwt
# password 암호화 라이브러리
import bcrypt

import datetime
import os
import mariadb
import sys


SECRET_KEY = "Blue-Bird"
print("현재 작업경로: ", os.getcwd())
print(os.listdir())
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

print(__name__)

@app.route('/')
def Index():
    print("현재 작업경로: ", os.getcwd())
    print(os.listdir())
    return render_template('login.html')
    
@app.route('/login', methods=['POST'])
def login():
    result = request.form
    userID = result.get('userID')
    userPW = result.get('userPW')
    print(userID, userPW)

    """
    userID, userPW 입력값이 비어있는지 확인
    """
    if not userID:
        return jsonify({"msg":"Username을 입력하세요. "})
    if not userPW:
        return jsonify({"msg":"Password를 입력하세요. "})

    """
    password 인코딩
    """
    # userPWencoded = userPW.encode('utf-8')

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
    cur.execute(f"SELECT password FROM auth.password WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}')")
    conn.commit()
    print(cur)
    rows = cur.fetchall()
    if rows:
        db_user_password = rows[0][0]

    else:
        return jsonify({"msg":"등록되지 않은 아이디입니다."})
  


    """
    해당 로그인 요청의 ID와 PW가 DB에 존재하는지, 일치하는지 확인
    """
    if bcrypt.checkpw(userPW.encode('utf-8'), db_user_password.encode('utf-8')):
        """
        정상적인 회원가입으로 DB에 등록된 사용자라면 access token과 refresh 토큰 발급
        이미 발급받은 토큰이 있다면 삭제
        """
        access_payload = {}
        refresh_payload = {}


        access_payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(seconds=15)
        access_payload["userID"] = userID

        refresh_payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(seconds=120)
        refresh_payload["userID"] = userID

        access_token = jwt.encode(
            payload = access_payload,
            key = SECRET_KEY, # 시크릿 키
            algorithm = "HS256", # 해싱 알고리즘
            )
        refresh_token = jwt.encode(
            payload = refresh_payload,
            key = SECRET_KEY, # 시크릿 키
            algorithm = "HS256", # 해싱 알고리즘
            )

        print(access_token)
        print(refresh_token)

        
        """ Refresh Token은 DB에 저장, 이미 있다면 삭제 """
        cur.execute(f"UPDATE auth.password SET refresh_token = '{refresh_token}' WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}')")
        conn.commit()
        
        cur.close()
        conn.close()

        """
        클라이언트의 cookie에 access token 값을 전달
        """
        res = make_response(render_template('authorized.html', userID = userID))
        res.set_cookie('access_token', access_token)
        return res
    
    else:
        return jsonify({"msg":"잘못된 비밀번호 입니다."})

@app.route('/sign-up', methods=['GET'])
def register():
    return render_template('sign-up.html')

@app.route('/manage', methods=['GET'])
def manage():

    """
    유저 인증이 필요한 서비스이므로 인증 토큰을 확인하는 데코레이터 구현
    """
    access_token = request.cookies.get('access_token')
    try:
        print(access_token)
        decoded_token = jwt.decode(
            access_token,
            SECRET_KEY,
            algorithms="HS256",
        )
        print(decoded_token)
    except jwt.ExpiredSignatureError:
        return jsonify({"msg":"토큰이 만료되었습니다!"})
    
    except jwt.InvalidTokenError:
        return jsonify({"msg":"유효하지 않은 토큰 입니다!"})
    
    else:
        return jsonify({"msg":"유저 관리 페이지로 이동합니다!"})

    """
    1) access token의 유효기간이 만료된 경우
     - 해당 유저의 DB에 저장된 refresh token을 확인하여 유효하지 않다면,
       에러 반환 (모든 토큰이 만료되었으므로 재로그인이 필요함)

     - refresh token이 유효하다면,
       access token을 재발급하여 클라이언트에게 쿠키로 전달
       이후 서비스 정상 처리 (유저 관리 페이지로 이동)

    2) access token이 유효한 경우
     - 해당 유저의 DB에 저장된 refresh token을 확인하여 유효하지 않다면,
       refresh token을 재발급하여 해당 유저의 DB에 갱신
       이후 서비스 정상 처리 (유저 관리 페이지로 이동)

     - refresh token이 유효하다면
       정상 처리(유저 관리 페이지로 이동)
    """


@app.route('/register', methods=['POST'])
def send():
    result = request.form
    print(result)
    userID = result.get('userID')
    if ( result.get('userPW') == result.get('reEnter') ):
        userPW = result.get('userPW')
    name = result.get('name')
    nickname = result.get('nickname')
    introduction = result.get('introduction')
    cell_phone = result.get('cell_phone')
    birth = result.get('yy') + '-' + result.get('mm') + '-' + result.get('dd')
    gender = result.get('gender')
    gather_agree = result.get('gather_agree')
    print(
        '\n',
        "아이디:", userID, "\n",
        "비밀번호:", userPW, "\n",
        "성함:", name, "\n",
        "닉네임:", nickname, "\n",
        "자기소개:", introduction, "\n",
        "휴대전화:", cell_phone, "\n",
        "생년월일:", birth, "\n",
        "성별:", gender, "\n",
        "개인정보 수집동의:", gather_agree)
    
    """
    password Encryption

    bcrypt를 이용한 password 단방향 암호화 후 DB 저장
    암호화-평문으로 복호화가 어려워
    서버에서도 회원의 비밀번호를 알아내는 것이 불가능하며
    회원이 입력한 비밀번호와 일치하는지 여부만 알 수 있다
    """
    
    # 암호화 함수는 오직 bytes string에서만 작동 하므로 utf-8 인코딩을 해주어야 함
    # bcrypt.gensalt()를 통해 자동으로 랜덤 salt 값을 받을 수 있음
    # 로그인 시에는 저장되어 있는 salt값과 매칭이 되는지 확인하므로 check시 salt값을 기억하고 있을 필요없음
    userSalt = bcrypt.gensalt()
    userPWhash = bcrypt.hashpw(userPW.encode('utf-8'), userSalt) 
    userPWhash = userPWhash.decode('utf-8')
    print(type(userPWhash), sys.getsizeof(userPWhash)) 
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
    print(cur)

    # member.user 테이블에 UUID로 생성되는 user_no와 입력된 userID 등록
    cur.execute(f"INSERT INTO member.user(user_no, user_id) VALUES(UUID(), '{userID}');")
    # member.profile 테이블에 외래 키인 UUID로 생성된 user_no를 찾아서 입력된 name, nickname, introduction와 함께 등록
    cur.execute(f"INSERT INTO member.profile(user_no, name, nickname, introduction) VALUES((SELECT user_no FROM member.user WHERE (user_id = '{userID}')),'{name}', '{nickname}','{introduction}');")
    # member.authenctication 테이블에 외래 키인 UUID로 생성된 user_no를 찾아서 입력된 gather_agree, cell_phone, birthday, sex와 함께 등록
    cur.execute(f"INSERT INTO member.authenctication(user_no, gather_agree, cell_phone, birthday, sex) VALUES((SELECT user_no FROM member.user WHERE (user_id = '{userID}')), {gather_agree},'{cell_phone}','{birth}',{gender});")
    # auth.password 테이블에 외래 키인 UUID로 생성된 user_no를 찾아서 단방향 암호화된 userPW와 함께 등록
    cur.execute(f"INSERT INTO auth.password(user_no, password) VALUES((SELECT user_no FROM member.user WHERE (user_id = '{userID}')),'{userPWhash}');")
    conn.commit()
    cur.close()
    conn.close()

    return render_template('success.html', name = nickname)


if __name__ == "__main__":
    app.run(debug=True)