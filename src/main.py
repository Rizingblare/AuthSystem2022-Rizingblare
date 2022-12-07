from flask import Flask, render_template, request
import os
print("현재 작업경로: ", os.getcwd())
print(os.listdir())
app = Flask(__name__)
print(__name__)

@app.route('/')
def Index():
    print("현재 작업경로: ", os.getcwd())
    print(os.listdir())
    return render_template('index.html')
    
@app.route('/login', methods=['POST'])
def login():
    result = request.form
    userID = result.get('myID')
    print(userID)
    return render_template('index.html')

@app.route('/register', methods=['GET'])
def register():
    return render_template('register.html')


if __name__ == "__main__":
    app.run(debug=True)