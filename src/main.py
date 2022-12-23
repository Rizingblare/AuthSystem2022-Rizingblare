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
token_type = {'access' : 0, 'refresh' : 1}
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

print(__name__)


def get_db_connection():
    try:
        conn = mariadb.connect(
            user = "root",
            password = "0000",
            host = "127.0.0.1",
            port = 3306,
        )

    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")
        sys.exit(1)
    
    return conn

def token_generator(tokenType, userID):
    # tokenType이 0이면 access token, 1이면 refresh token 발급
    payload = {}

    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(seconds = (90 if tokenType else 15))
    payload['userID'] = userID
    
    token = jwt.encode(
        payload = payload,
        key = SECRET_KEY, # 시크릿 키
        algorithm = "HS256", # 해싱 알고리즘
    )

    return token
    
def token_verify_exp(token):
    # 해당 토큰이 유효하다면 0, 만료되었다면 1 반환

    try:
        decode_token = jwt.decode(
            token,
            SECRET_KEY,
            algorithms="HS256",
        )

    except jwt.ExpiredSignatureError:
        return 1
    
    else:
        return 0

@app.route('/')
def Index():
    print("현재 작업경로: ", os.getcwd())
    print(os.listdir())
    return render_template('login.html')
    
@app.route('/login', methods=['POST'])
def login():
    userID = request.form.get('userID')
    userPW = request.form.get('userPW')
    
    # userID, userPW 입력값이 비어있는지 확인
    if not userID:
        return render_template('message.html', msg = f"오류: Username을 입력하세요.")
    if not userPW:
        return render_template('message.html', msg = f"오류: Password를 입력하세요.")

    # 해당 로그인 요청의 ID와 PW가 DB에 존재하는지, 일치하는지 확인
    conn = get_db_connection()
    cur = conn.cursor()

    query = f"SELECT password FROM auth.password WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}');"
    cur.execute(query)
    conn.commit()

    subscribed = cur.fetchall()
    cur.close()
    conn.close()
    
    if subscribed:
        db_user_password = subscribed[0][0]

    else:
        return render_template('message.html', msg = f"오류: 등록되지 않은 아이디입니다.")

    # 입력받은 비밀번호와 DB에 저장된 유저 비밀번호의 일치여부 확인
    if bcrypt.checkpw(userPW.encode('utf-8'), db_user_password.encode('utf-8')):
        """
        정상적인 회원가입으로 DB에 등록된 사용자라면 access token과 refresh 토큰 발급
        이미 발급받은 토큰이 있다면 삭제
        """
        access_token = token_generator(0, userID)
        refresh_token = token_generator(1, userID)
        
        # Refresh Token은 DB에 저장, 이미 있다면 삭제
        conn = get_db_connection()
        cur = conn.cursor()

        query = f"UPDATE auth.password SET refresh_token = '{refresh_token}' WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}');"
        cur.execute(query)
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
        return render_template('message.html', msg = f"오류: 잘못된 비밀번호 입니다.")


@app.route('/sign-up', methods=['GET'])
def register():
    return render_template('sign-up.html')

@app.route('/manage', methods=['GET'])
def manage():
    ### 보완하고 싶은 점: 인증 토큰을 검증하는 프로세스를 데코레이터를 구현하기

    access_token = request.cookies.get('access_token')

    payload = jwt.decode(access_token, options={"verify_signature": False})
    userID = payload['userID']
    conn = get_db_connection()
    cur = conn.cursor()

    query = f"SELECT refresh_token FROM auth.password WHERE user_no = (SELECT user_no FROM member.user WHERE (user_id = '{userID}'));"
    cur.execute(query)
    conn.commit()

    refresh_token = cur.fetchall()[0][0]
    cur.close()
    conn.close()

    token_expired = token_verify_exp(access_token)

    if token_expired:
        # 1) access token의 유효기간이 만료된 경우
        print("access_token이 만료되었습니다!")

        if refresh_token:
            token_expired = token_verify_exp(refresh_token)

            if token_expired:
                print("refresh_token이 만료되었습니다!")
                """
                    - 해당 유저의 DB에 저장된 refresh token을 확인하여 유효하지 않다면,
                    에러 반환 (모든 토큰이 만료되었으므로 재로그인이 필요함)
                """
                return render_template('message.html', msg = f"오류: 모든 토큰이 만료되어 재로그인이 필요합니다!")

            else:
                """
                    - refresh token이 유효하다면, access token을 재발급하여 클라이언트에게 쿠키로 전달
                    이후 서비스 정상 처리 (유저 관리 페이지로 이동)
                """
                access_token = token_generator(0, userID)
                print("access_token을 재발급하였습니다!")
                res = make_response(render_template('user-manage.html', userID = userID))
                res.set_cookie('access_token', access_token)
                return res
        else:
            return render_template('message.html', msg = f"오류: refresh 토큰이 존재하지 않습니다!")

    else:
        # 2) access token이 유효한 경우
        if refresh_token:
            token_expired = token_verify_exp(refresh_token)

            if token_expired:
                print("refresh_token이 만료되었습니다!")
                """
                    - 해당 유저의 DB에 저장된 refresh token을 확인하여 유효하지 않다면,
                    refresh token을 재발급하여 해당 유저의 DB에 갱신
                    이후 서비스 정상 처리 (유저 관리 페이지로 이동)
                """
                refresh_token = token_generator(1, userID)

                conn = get_db_connection()
                cur = conn.cursor()

                query = f"UPDATE auth.password SET refresh_token = '{refresh_token}' WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}')"
                cur.execute(query)
                conn.commit()

                cur.close()
                conn.close()

                print("refresh_token을 재발급하였습니다!")
                return render_template('user-manage.html')

            else:
                """
                    - refresh token이 유효하다면
                    정상 처리(유저 관리 페이지로 이동)
                """
                print("인증 요청이 정상처리 되었습니다.")
                return render_template('user-manage.html')

        else:
            return render_template('message.html', msg = f"오류: refresh 토큰이 존재하지 않습니다!")



@app.route('/register', methods=['POST'])
def send():
    result = request.form

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

    conn = get_db_connection()
    cur = conn.cursor()

    # member.user 테이블에 UUID로 생성되는 user_no와 입력된 userID 등록
    query = f"INSERT INTO member.user(user_no, user_id) VALUES(UUID(), '{userID}');"
    cur.execute(query)

    # member.profile 테이블에 외래 키인 UUID로 생성된 user_no를 찾아서 입력된 name, nickname, introduction와 함께 등록
    query = f"INSERT INTO member.profile(user_no, name, nickname, introduction) VALUES((SELECT user_no FROM member.user WHERE (user_id = '{userID}')),'{name}', '{nickname}','{introduction}');"
    cur.execute(query)

    # member.authenctication 테이블에 외래 키인 UUID로 생성된 user_no를 찾아서 입력된 gather_agree, cell_phone, birthday, sex와 함께 등록
    query = f"INSERT INTO member.authenctication(user_no, gather_agree, cell_phone, birthday, sex) VALUES((SELECT user_no FROM member.user WHERE (user_id = '{userID}')), {gather_agree},'{cell_phone}','{birth}',{gender});"
    cur.execute(query)

    # auth.password 테이블에 외래 키인 UUID로 생성된 user_no를 찾아서 단방향 암호화된 userPW와 함께 등록
    query = f"INSERT INTO auth.password(user_no, password) VALUES((SELECT user_no FROM member.user WHERE (user_id = '{userID}')),'{userPWhash}');"
    cur.execute(query)

    conn.commit()
    cur.close()
    conn.close()

    return render_template('message.html', msg = f"{nickname}님 가입이 완료되었습니다 !")


if __name__ == "__main__":
    app.run(debug=True)