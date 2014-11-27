#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, request, session
from Model import *
from pony.orm import *
from pony.orm.serialization import to_dict
import json
from functools import wraps
import cronwork

app = Flask(__name__)

if Config.get('debug'):
    app.debug = True

def with_permission(func):
    @wraps(func)
    def _check_permission(**args):
        username = args['username']
        u = User.get(student_id=str(username))
        if not u:
            return json.dumps({'result':False, 'msg':'No such user'})
        if request.form.has_key('token'):
            token = request.form['token']   
        elif request.args.get('token'):
            token = request.args.get('token')
        elif session.has_key('token'):
            token = session['token']
        token = Token.get(user=u, token=token)
        if not token:
            return json.dumps({'result':False, 'msg':'Permission denied'})
        if token.is_expired():
            return json.dumps({'result':False, 'msg':'Token expired'})
        return func(u, **args)
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

@app.route("/api/user/<int:username>", methods=['GET'])
@db_session
@with_permission
def user(u, username):
    r = get(s for s in StudentInfo if s.StudentID==username)
    u = u.to_dict(exclude='password')
    s = r.to_dict()
    result = dict(u, **s)
    return json.dumps({'result':True, 'user':result}) 

@app.route("/api/user/<int:username>", methods=['POST'])
@db_session
@with_permission
def user_edit(u, username):
    form = {}
    for i in request.form:
        if i in ['password','email','phone','ykt']:
            form[i] = request.form[i]
    if form:
        u.set(**form)
        u.flush()
        return json.dumps({'result':True, 'user':u.to_dict(exclude='password')})
    return json.dumps({'result':False})


@app.route("/")
def index():
    return 'hello world'   

if __name__ == '__main__':
    cronwork.start()
    if Config.get('develop'):
        app.run(host='0.0.0.0', use_reloader=False)
    else:
        app.run(host='0.0.0.0', use_reloader=False)
