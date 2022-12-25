# 인증 시스템
## 개요
JWT과 Python 라이브러리를 이용한 유저 인증 시스템 구현

## 기술스택
- Python 3.9.13
- Flask 2.2.2
- JWT
- MariaDB

## 제공기능

|기능|설명|
|---|---|
|회원가입|필요한 정보를 입력받아 신규 회원 등록|
|회원관리|로그인 인증을 거친 후에 회원들의 개인정보를 열람하고 탈퇴시킬 수 있는 기능|

## 사용한 라이브러리
- Flask 2.2.2
- PyJWT 2.6.0
- bcrypt 4.0.1
- mariadb 1.1.5.post3

## 화면 UI

- 로그인 페이지
![image](https://user-images.githubusercontent.com/77480122/209466061-4cd098d2-97e1-48cb-a18a-ec4a89b4bd3d.png)

- 회원가입 페이지
![image](https://user-images.githubusercontent.com/77480122/209466198-1a38ad6b-ed24-40c6-b302-445d141c94a2.png)

- 회원 페이지
![image](https://user-images.githubusercontent.com/77480122/209466112-1603c313-aab5-43d5-8736-9b717adb896c.png)

- 유저 관리 페이지
![image](https://user-images.githubusercontent.com/77480122/209466337-642f8e10-48df-49ee-92eb-b9665294d8be.png)

- 메세지 전달 페이지
![image](https://user-images.githubusercontent.com/77480122/209466392-19c7e79a-ded1-49f1-ac93-8a9b4495be81.png)


## 구현
- [main.py](.src/main.py)

### JWT 인증
```python
@app.route('/login', methods=['POST'])
def login():
    ...
    
    # 해당 로그인 요청의 ID와 PW가 DB에 존재하는지, 일치하는지 확인
    conn = get_db_connection()
    cur = conn.cursor()

    query = f"SELECT password FROM auth.password WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}');"
    cur.execute(query)
    conn.commit()

    subscribed = cur.fetchall()
    ...
    
    if subscribed:
        db_user_password = subscribed[0][0]

    else:
        return render_template('message.html', msg = f"오류: 등록되지 않은 아이디입니다.")

    # 입력받은 비밀번호와 DB에 저장된 유저 비밀번호의 일치여부 확인
    if bcrypt.checkpw(userPW.encode('utf-8'), db_user_password.encode('utf-8')):
    
        access_token, access_timeout_msg = token_generator(0, userID)
        refresh_token, refresh_timeout_msg = token_generator(1, userID)
        
        # Refresh Token은 DB에 저장, 이미 있다면 삭제
        ...
        query = f"UPDATE auth.password SET refresh_token = '{refresh_token}' WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}');"
        ...
        
        # 클라이언트의 cookie에 access token 값을 전달
        res = make_response(render_template('authorized.html', userID = userID, r_msg = refresh_timeout_msg))
        res.set_cookie('access_token', access_token)
        return res
    
    else:
        return render_template('message.html', msg = f"오류: 잘못된 비밀번호 입니다.")
```

### JWT 인가
```python
@app.route('/manage', methods=['GET'])
def manage():
    access_token = request.cookies.get('access_token')
    try:
        payload = jwt.decode(access_token, options={"verify_signature": False})

    except jwt.InvalidTokenError:
        # 로그인 인증 없이 서비스에 접근하는 경우
        return render_template('message.html', msg = f"오류: 유효하지 않은 접근입니다!")

    else:
        ...

        token_expired = token_exp_verify(access_token)

        if token_expired:
            # 1) access token의 유효기간이 만료된 경우
            if refresh_token:
                token_expired = token_exp_verify(refresh_token)

                if token_expired:
                    # 1-1) refresh token의 유효기간이 만료된 경우
                    return render_template('message.html', msg = f"오류: 모든 토큰이 만료되어 재로그인이 필요합니다!")

                else:
                    # 1-2) refresh token이 아직 유효한 경우
                    access_token, access_timeout_msg = token_generator(0, userID)
                    print("access_token을 재발급하였습니다!")

                    # 이후 서비스 정상 처리
                    user_dict = get_user_info()
                    res = make_response(render_template('user-manage.html', userID = userID, user_dict = user_dict))
                    res.set_cookie('access_token', access_token)

                    return res
            else:
                return render_template('message.html', msg = f"오류: refresh 토큰이 존재하지 않습니다!")

        else:
            # 2) access token이 유효한 경우
            if refresh_token:
                token_expired = token_exp_verify(refresh_token)

                if token_expired:
                    # 2-1) refresh token의 유효기간이 만료된 경우
                    refresh_token, refresh_timeout_msg = token_generator(1, userID)
                    
                    ...

                    query = f"UPDATE auth.password SET refresh_token = '{refresh_token}' WHERE user_no = (SELECT user_no FROM member.user WHERE user_id = '{userID}');"
                    cur.execute(query)
                    
                    ...

                    print("refresh_token을 재발급하였습니다!")

                    # 이후 서비스 정상 처리 (유저 관리 페이지로 이동)
                    user_dict = get_user_info()
                    return render_template('user-manage.html', userID = userID, user_dict = user_dict)

                else:
                    # 2-2) refresh token이 아직 유효한 경우
                    # 이후 서비스 정상 처리

                    user_dict = get_user_info()
                    return render_template('user-manage.html', userID = userID, user_dict = user_dict)

            else:
                return render_template('message.html', msg = f"오류: refresh 토큰이 존재하지 않습니다!")

```

## 수정 & 보완사항 및 고민
- SECRET_KEY와 같은 상수(환경 변수) 값들이나 DB Config 값들을 별도의 파일로 저장하고  
필요할 때 읽어와서 쓰는 식으로 관리하고 싶은데 구체적으로 어떤 값들을 어떻게 묶어서 관리해야 할지  
판단이 서질 않아서 실행에 옮기지 않았음<br>  


- 인증이 필요한 서비스에 토큰을 검증하는 프로세스를 Python Decorator와 같은 문법을 사용하여  
오버라이딩(?)해서 관리하고 싶은데 사용법이 익숙하지 않아서 적용하지 못했음<br>  


- UI 웹 디자인이 익숙하지 않아서 처음 html 파일을 생성할 때,  
구조를 비효율적으로 잡아서 이후에 CSS를 적용하느라 시간 낭비를 많이 하였음.  
html을 작성할 때 기본적으로 권장되는 사항들에 대한 학습이 필요한 것 같음.<br>  


- 라이브러리 사용을 지양하는 것이 어느 정도가 적정 수준인지 모르겠음.  
JWT도 직접 JSON 파일로 생성하고, 패스워드 hash & salt 함수도 직접 구현하여야 하는 것인지,  
모든 것을 다 직접 구현하는 것이 이상적인지 아니면 학습의 차원에서도 오히려 비효율적이진 않은지  
사이에서 고민을 많이 하였음<br>  


- 사용한 가상환경 파일들과 설치한 라이브러리들을 어떤 방식으로 저장해야할 지 모르겠음.  
더 구체적으로 이야기하면 어떤 파일들을 git에 저장해서 배포하고  
어떤 파일들을 ignore해야할지 판단이 서질 않음.<br>  


- 서비스 요청을 역할 단위로 묶어서 처리하는 서버를 다중화한다는  
MSA의 구조와 의도는 어느 정도 이해했지만 구체적으로 어떤 프로세스로 이를 구현할 수 있는지,  
도커Docker에서 이미지를 어떻게 저장해서 컨테이너를 어떻게 발생시켜야 하는지  
걸림돌에 가로막히는 부분이 너무 많다, 사용법도 아직 낯설고.<br>


- 네트워크에 대한 이해가 부족한 것 같기도 하다. 한 PC에서 여러 서버를 작동시키려고 할때,  
필요한 포트에 대한 개념도 그렇고, cookie나 session, 그리고 cash와 같은 클라이언트 측이 소유하고 있는 것,  
할 수 있는 것과 운용할 수 있는 것에 대한 개념도 거의 없다는 것을 느낌.
