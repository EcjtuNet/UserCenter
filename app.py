#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, request, session
from Model import *
from pony.orm import *
from pony.orm.serialization import to_dict
import json
from functools import wraps

app = Flask(__name__)

if Config.get('develop'):
    app.debug = True

def with_permission(func):
    @wraps(func)
    def _check_permission(**args):
        student_id = args['student_id']
        u = User.getBySid(str(student_id))
        if not u:
            return json.dumps({'result':False, 'msg':'No such user'})        
        if request.form.has_key('token'):
            token = request.form['token']   
        elif request.args.get('token'):
            token = request.args.get('token')
        elif session.has_key('token'):
            token = session['token']
        else:
            return json.dumps({'result':False, 'msg':'Permission denied'})        
        if not Token.get(token=token):
            return json.dumps({'result':False, 'msg':'Permission denied'})        
        return func(**args)
    return _check_permission
   
@app.route("/api/login", methods=['POST'])
@db_session
def login():
    username = request.form['username']
    password = request.form['password']
    u = User.login(username, password)
    if u:
        return json.dumps({'result':True,'token':u.token.to_dict()['token']})
    else:
        return json.dumps({'result':False, 'msg':'Username or password is incorrect', 'token':''})
    
@app.route("/api/register", methods=['POST'])
@db_session
def register():
    username = request.form['username']
    password = request.form['password']
    if User.is_exist(username):
        return json.dumps({'result':False, 'msg':'Username exist'})
    u = User.register(username, password)
    if u:
        return json.dumps({
            'result':True,
            'msg':'ok',
            'user':u.to_dict()
            })
    else:
        return json.dumps({'result':False, 'msg':'Register error'})

@app.route("/api/user/<int:username>")
@db_session
def user():
    token = Token.get(user=username, token=request.args.get('token'))
    if not token:
        return json.dumps({'result':False, 'msg':'Permission denied'})
    if token.is_expired():
        return json.dumps({'result':False, 'msg':'Token expired'})
    return json.dumps({'result':True, 'user':token.user.to_dict(exclude='password')}) 

@app.route("/")
def index():
    return 'hello world'   

if __name__ == '__main__':
    if Config.get('develop'):
        app.run(host='0.0.0.0', use_reloader=False)
    else:
        app.run(host='0.0.0.0', use_reloader=False)
