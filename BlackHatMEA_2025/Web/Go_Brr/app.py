from flask import Flask, request, session
import requests
import secrets
import os


app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

auth_service_url = 'http://localhost:8082/user'

@app.route('/user', methods=['POST'])
def user_handler():
    data = request.get_json() or None
    if data is None or not "username" in data or not "password" in data:
        return "Invalid data format (not a valid JSON schema)", 400
    check = requests.post(auth_service_url, json=data).text
    if check == '"Authorized"':
        session['is_admin'] = True
        return "Authorized"
    else:
        return "Not Authorized", 403
    

@app.route('/admin', methods=['GET'])
def admin_panel():
    if session.get('is_admin'):
        flag = os.getenv('DYN_FLAG', 'BHFlagY{dummy_flag_for_testing}')
        return "Welcome to the admin panel! Here is the flag: " + flag
    else:
        return "Access denied", 403

app.run(host='0.0.0.0', port=8081)