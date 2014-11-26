#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pony.orm import *
import Config
import hashlib
import time

if Config.get('develop') == True:
    db = Database('sqlite', 'test.sqlite', create_db=True)
    sql_debug(True)
else:
    db = Database('mysql', host=Config.get('host'), user=Config.get('user'), passwd=Config.get('passwd'), db=Config.get('db'))

class User(db.Entity):
    password = Optional(str)
    student_id = PrimaryKey(str)
    email = Optional(str, unique=True)
    phone = Optional(str)
    ykt = Optional(str)
    reg_time = Required(str)
    tokens = Set(lambda: Token)

    @classmethod
    def getBySid(cls, student_id):
        return User.get(student_id=student_id)

    @classmethod
    def login(cls, username, password):
        u = User.get(student_id=username)
        if not u or u.password=='':
            s = StudentInfo.get(StudentID=username)
            if s.IDCard[-6:]==password:
                u = User(student_id=username, reg_time = str(int(time.time())))
                u.password = User._salt(username, password)
                u._setToken()
                return u
            else:
                return False
        elif u.password==User._salt(username, password):
            u._setToken()
            return u
        else:
            return False
    
    @classmethod
    def register(cls, username, password):
        return User(
                name=username, 
                student_id=username, 
                password=User._salt(username, password), 
                reg_time=str(int(time.time()))
                )
   
    @classmethod
    def is_exist(cls, username):
        return User.get(student_id=username) 
        
    def _setToken(self):
        self.token = self.tokens.create(token=User._makeToken(self.student_id), last_use_time=str(int(time.time())))

    @classmethod
    def _salt(self, username, password):
        return password #!!!
        return hashlib.sha256(str(username) + \
                str(hashlib.sha256(str(password)+str(Config.get('salt'))).hexdigest())).hexdigest()

    @classmethod
    def _makeToken(self, username):
        return str(hashlib.md5(str(username)+str(int(time.time()))).hexdigest())

class Token(db.Entity):
    user = Required(User)
    token = Required(str)
    last_use_time = Required(str)

    def is_expired(self):
        if int(time.time()) - int(self.last_use_time) < Config.get('token_expire'):
            self.last_use_time = str(int(time.time()))
            return False
        else:
            return True

class StudentInfo(db.Entity):
    StudentID = PrimaryKey(str)
    ClassCode = Optional(str)
    Name = Optional(str)
    Sex = Optional(str)
    Birth = Optional(str)
    Nationality = Optional(str)
    Political = Optional(str)
    EduType = Optional(str)
    Classify = Optional(str)
    Source = Optional(str)
    Native = Optional(str)
    Class = Optional(str)
    EducationLen = Optional(str)
    DiplomaNo = Optional(str)
    DgreeNo = Optional(str)
    StudyFlag = Optional(str)
    PunishFlag = Optional(str)
    IDCard = Optional(str)
    KSH = Optional(str)
    
db.generate_mapping(create_tables=True)
