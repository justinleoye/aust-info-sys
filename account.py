#!/usr/bin/env python
#-*- coding: utf-8 -*-

import web
import urllib
import re
import cgi
from setting import render

from setting import load_sqla
from models import User
#valid useful functions
def escape_html(s):
    return cgi.escape(s, quote = True)

USERID_RE = re.compile(r"^[0-9]{1,11}$")
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
TEL_RE = re.compile(r"^[0-9]{11}$")
QQ_RE = re.compile(r"^[0-9]{1,13}$")

USER_AGENT_RE = re.compile(r"(Firefox\/[0-9]{1,3}|Chrome\/[0-9]{1,3}|MSIE\s[0-9]{1,3}|Safari\/[0-9]{1,3})")

def valid_userid(userid):
    userid = str(userid)
    if userid:
        return USERID_RE.match(userid)

def valid_name(name):
    if name:
        return USER_RE.match(name)

def valid_password(password):
    if password:
        return PASSWD_RE.match(password)

def verify_password(password, v_password):
    if v_password and password == v_password:
        return v_password

def valid_email(email):
    if email:
        return EMAIL_RE.match(email)

def valid_tel(tel):
    if tel:
        return TEL_RE.match(tel)
def valid_qq(qq):
    if qq:
        return QQ_RE.match(qq)





import random
import string
import hashlib

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(pw):
    salt = make_salt()
    h = hashlib.sha256(pw + salt).hexdigest()
    return '%s,%s' %(h,salt)

def valid_pw(pw_h):
    if pw_h:
        h = pw_h.split('|')
    else:
        return False
        
    #user = User.get_by_id(int(h[0]))
    user = web.ctx.orm.query(User).filter_by(username=h[0]).first()

    if user:
        if h[1] == user.userpass:
            return user
        else:
            return False
        
def verify_pw(pw,pw_h,salt):
    if pw and pw_h and salt:
        
        if pw_h == hashlib.sha256(pw + salt).hexdigest():
            return True

#some useful funcs
#get info of a user
def get_user(userid):
    #userid=str(userid)
    if valid_userid(userid):
        user = web.ctx.orm.query(User).filter_by(userid=userid).first()
        if user:
            return user
        else:
            return None

class Account():
    account = None

    def __init__(self):
        pass
    
    def valid(self):
        cookie_user = web.cookies().get('user')
        user = valid_pw(cookie_user)
        if user:
            return user
        else:
            #delete the cookie
            web.setcookie('user','')
            return None

    def signin(self, email, password):
        valided_email = valid_email(email)
        valided_password = valid_password(password)
        
        if valided_email and valided_password:
            #validation success,access the database
            users = web.ctx.orm.query(User).filter_by(email=email).all()
            if users:
                user = users[0]
                userid = user.userid

                if verify_pw(password, user.userpass, user.salt):
                    self.account = {
                            user: user
                        }
                    self.set_cookies(user)
                    return {result: True, error: None}
            else:
                return {result: False, error: 'The user is not exist,or the password does not match this acount!oops!'}
        else:
            return {result: False, error: 'The input name or password is invalid!oops!'}


    def signup(self,username,password,v_password,email,qq):
        valided_username = valid_name(username)
        valided_password = valid_password(password)
        verified_password = verify_password(password, v_password)
        valided_email = valid_email(email)
        valided_qq = valid_qq(qq)

        username_error = ''
        password_error = ''
        v_password_error = ''
        email_error = ''
        qq_error = ''
        terms_error = ''

        if not valided_username:
            username_error = u'用户名是3到20个英文字符、数字或者“-”'

        if not valided_password:
            password_error = u"至少3个字符，最多20个字符，区分大小写"
        elif not verified_password:
            v_password_error = u"两次输入的密码不相同"

        if not valided_email:
            email_error = u"输入的邮箱不正确"

        if not valided_qq:
            qq_error = u"输入的QQ号不正确"
            
        if not terms:
            terms_error = u"The terms not been checked"

        if username_error == '' and password_error == '' and v_password_error == '' and email_error == '' and qq_error=='' and terms_error == '':
            #Access the database and do something cool
            user = web.ctx.orm.query(User).filter_by(username=username).first()
            email_user = web.ctx.orm.query(User.email).filter_by(email=email).first()
            if not user and not email_user:
                h = (make_pw_hash(password)).split(',')
                pw_h = h[0]
                salt = h[1]
                u = User(
                    username = username,
                    userpass =pw_h,
                    salt =salt,
                    email =email,
                    qq = qq
                )
                web.ctx.orm.add(u)
                # need signin here

                self.set_cookies(u)
                return {result: True,error: None}
            else:
                if user:
                    username_error = u'该用户名已经被使用！'
                    user=None
                if email_user:
                    email_error = u'该邮箱已经注册过，不能重复注册！'
                    email_user=None
                return {result: False, error: 
                        {
                            username_error: username_error,
                            email_error: email_error,
                            qq_error: qq_error
                        }
                    }
        else:
            username = escape_html(username)
            email = escape_html(email)
            user=None
            return {result: False, error:
                    {
                        username_error: username_error,
                        password_error: password_error,
                        v_password_error: v_password_error,
                        email_error: email_error,
                        qq_error: qq_error,
                        terms_error: terms_error
                    }
                }
        

    def signout(self):
        self.del_cookies()
        return True

    def get_account(self):
        return self.account

    def update_account(self,account):
        if self.is_valid():
            email = account.email
            qq = account.qq

            valided_email = valid_email(email)
            valided_qq = valid_qq(qq)

            email_error = ''
            qq_error = ''

            if not valided_email:
                email_error = u'您输入的email有错误！'

            if not valided_qq:
                qq_error = u'您输入的QQ号有错误！'

            if email_error == '' and qq_error == '':
                self.account.user.email = email
                self.account.user.qq = qq
                return {result: True, error: None}

            else:
                return {result: False, code: 300, error:
                        {
                            email_error: email_error,
                            qq_error: qq_error
                        }
                    }
        else:
            return {result: False, code: 502, error:
                    {
                        error: 'not valid user'
                    }
                }


    def del_account(self):
        if self.is_valid():
            user = self.account.user
            web.ctx.orm.delete(user)
            return {result: True, code: 200, error: None}
        else:
            return {result: False, code: 502, error:
                    {
                        error: 'not valid user'
                    }
                }


    def is_valid(self):
        if self.account != None:
            return True
        else:
            return False

    def set_cookies(self,user):
        cookie_user = '%s|%s' % (user.username, user.userpass)
        #set cookie
        web.setcookie('user',cookie_user)

    def del_cookies(self):
        #delete the cookie
        web.setcookie('user','')

