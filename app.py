#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, redirect, url_for, abort, make_response
from Model import *
from pony.orm import *
from pony.orm.serialization import to_dict
import json
from functools import wraps
import cronwork
app = Flask(__name__)

if Config.get('debug'):
    app.debug = True

def get_token(request):
    if request.cookies.get('uc_token'):
        token = request.cookies.get('uc_token')
    if request.form.has_key('token'):
        token = request.form['token']   
    if request.args.get('token'):
        token = request.args.get('token')
    return token


def with_permission(func):
    @wraps(func)
    def _check_permission(**args):
        username = args['username'] if 'username' in args else request.cookies.get('student_id')
        u = User.get(student_id=str(username))
        if not u:
            return json.dumps({'result':False, 'msg':'No such user'})
        token = get_token(request)
        if not token:
            return json.dumps({'result':False, 'msg':'Permission denied'})
        token = Token.get(user=u, token=token)
        if not token:
            return json.dumps({'result':False, 'msg':'Permission denied'})
        if token.is_expired():
            return json.dumps({'result':False, 'msg':'Token expired'})
        args['username'] = u.student_id
        return func(u, **args)
    return _check_permission

@app.route("/api/login", methods=['POST'])
@db_session
def api_login():
    username = request.form['username']
    password = request.form['password']
    u = User.login(username, password)
    if u:
        return json.dumps({'result':True,'token':u.token.to_dict()['token']})
    else:
        return json.dumps({'result':False, 'msg':'Username or password is incorrect', 'token':''})
    
@app.route("/api/register", methods=['POST'])
@db_session
def api_register():
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
def api_user(u, username):
    r = get(s for s in StudentInfo if s.StudentID==username)
    u = u.to_dict(exclude='password')
    s = r.to_dict()
    result = dict(u, **s)
    return json.dumps({'result':True, 'user':result}) 

@app.route("/api/user/<int:username>", methods=['POST'])
@db_session
@with_permission
def api_user_edit(u, username):
    form = {}
    for i in request.form:
        if i in ['password','email','phone','ykt']:
            form[i] = request.form[i]
    if form:
        u.set(**form)
        u.flush()
        return json.dumps({'result':True, 'user':u.to_dict(exclude='password')})
    return json.dumps({'result':False})

@app.route("/login", methods=['GET'])
@db_session
def show_login():
    token = get_token(request)
    if token:
        t = Token.get(token=token)
        if not t.is_expired():
            return redirect(url_for('show_user'))
    return render_template('login.html')

@app.route("/login", methods=['POST'])
@db_session
def login():
    username = request.form['username']
    password = request.form['password']
    redirect_url = request.args.get('redirect') if request.args.get('redirect') else url_for('show_user')
    u = User.login(username, password)
    if u:
        resp = make_response(redirect(redirect_url))
        expires = int(time.time()) + Config.get('cookie_expire')
        resp.set_cookie('student_id', u.student_id, expires=expires, domain='.ecjtu.net')
        resp.set_cookie('uc_token', u.token.to_dict()['token'], expires=expires, domain='.ecjtu.net')
        return resp
    else:
        return render_template('login.html', error=True)

@app.route("/user", methods=['GET'])
@db_session
@with_permission
def show_user(u, username):
    r = get(s for s in StudentInfo if s.StudentID==username)
    data = u.to_dict(exclude='password')
    data = dict(data, **(r.to_dict()))
    print data
    return render_template('user.html', **data)

@app.route("/")
def index():
    return redirect(url_for('show_login'))

if __name__ == '__main__':
    cronwork.start()
    if Config.get('debug'):
        app.run(host='0.0.0.0', use_reloader=True)
    else:
        app.run(host='0.0.0.0', use_reloader=False)
