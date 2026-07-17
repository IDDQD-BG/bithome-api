import os
from flask import Flask
from backend.auth import auth_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    return response

@app.route('/')
def root():
    return {'status': 'bithome API running', 'version': '1.0'}
