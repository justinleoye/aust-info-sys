#!/usr/bin/env python
#-*- coding: utf-8 -*-
import web
import urllib
import re
import cgi
import json
from setting import render

from setting import load_sqla
from models import User,UserProfile
#valid useful functions
def escape_html(s):
    return cgi.escape(s, quote = True)

USERID_RE = re.compile(r"^[0-9]{1,11}$")
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
TEL_RE = re.compile(r"^[0-9]{11}$")
QQ_RE = re.compile(r"^[0-9]{1,13}$")
IDENTITY_RE = re.compile(r"^[0-9]{18,19}$")

USER_AGENT_RE = re.compile(r"(Firefox\/[0-9]{1,3}|Chrome\/[0-9]{1,3}|MSIE\s[0-9]{1,3}|Safari\/[0-9]{1,3})")

def valid_userid(userid):
    userid = str(userid)
    if userid:
        return USERID_RE.match(userid)
    return False

def valid_usertype(usertype):
    if usertype in ['student','teacher']:
        return True
    return False

def valid_name(name):
    if name:
        return USER_RE.match(name)
    return False

def valid_password(password):
    if password:
        return PASSWD_RE.match(password)
    return False

def verify_password(password, v_password):
    if v_password and password == v_password:
        return v_password
    return False

def valid_email(email):
    if email:
        return EMAIL_RE.match(email)
    return False

def valid_tel(tel):
    if tel:
        return TEL_RE.match(tel)
    return False

def valid_qq(qq):
    if qq:
        return QQ_RE.match(qq)
    return False

def valid_identity(identity):
    if identity:
        return IDENTITY_RE.match(identity)
    return False

def valid_address(address):
    if address:
        return True
    return False

def valid_family_info(family_info):
    if family_info:
        try:
            family_info_json = json.loads(family_info)
            for item in family_info_json:
                # 检查是否有少的域
                if not item.has_key('name') or not item.has_key('relationship') or not item.has_key('work_place') or not item.has_key('contact'):
                    print 'item:',item
                    print 'keys not valided'
                    return False
            return True
        except (ValueError),e:
            print 'Json parse error:',e
            return False
    return False

def parse_family_info(family_info):
    try:
        return json.loads(family_info)
    except (ValueError),e:
        return None

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

class AcountHandler:
    def redirect(self,path):
        web.seeother(path)
        
    def valid(self):
        cookie_user = web.cookies().get('user')
        user = valid_pw(cookie_user)
        if user:
            return user
        else:
            #delete the cookie
            web.setcookie('user','')
            return None
    def check_user_agent(self):
        if web.ctx.env.has_key('HTTP_USER_AGENT'):
            user_agent = web.ctx.env['HTTP_USER_AGENT']
            result = USER_AGENT_RE.findall(user_agent)
            for agent in result:
                if agent.startswith('MSIE'):
                    if int(agent[4::]) <9:
                        return False
        return True

class SignupHandler(AcountHandler):
    def write_html(self,user=None, usertype='', username='', email='', username_error='', password_error='', v_password_error='', email_error='', terms_error=''):
        return render.signup(user=user, usertype=usertype, username=username, email=email, username_error=username_error, password_error=password_error, v_password_error=v_password_error, email_error=email_error, terms_error=terms_error)
        
    def GET(self):
        user= self.valid()
        return self.write_html(user)

    def POST(self):
        i=web.input()
        usertype = i.usertype
        username = i.username
        password = i.password
        v_password = i.verify
        email = i.email
        try:
            terms = i.terms
        except: 
            terms = ''
        
        # 由于没有对邮箱进行邮件验证，所以有拿别人邮箱帐号注册，并伪造老师帐号的危险，这里以后再做严格的验证方式,例如，教师必要要输入邀请码进行自行激活,这样就把验证的工作转到了现实生活，验证的可信度就更高了
        valided_usertype = valid_usertype(usertype)
        valided_username = valid_name(username)
        valided_password = valid_password(password)
        verified_password = verify_password(password, v_password)
        valided_email = valid_email(email)

        usertype_error = ''
        username_error = ''
        password_error = ''
        v_password_error = ''
        email_error = ''
        terms_error = ''

        if not valided_usertype:
            usertype_error = u'用户类型'

        if not valided_username:
            username_error = u'用户名是3到20个英文字符、数字或者“-”'

        if not valided_password:
            password_error = u"至少3个字符，最多20个字符，区分大小写"
        elif not verified_password:
            v_password_error = u"两次输入的密码不相同"

        if not valided_email:
            email_error = u"输入的邮箱不正确"

        if not terms:
            terms_error = u"The terms not been checked"

        if username_error == '' and password_error == '' and v_password_error == '' and email_error == '' and terms_error == '':
            #Access the database and do something cool
            user = web.ctx.orm.query(User).filter_by(username=username).first()
            email_user = web.ctx.orm.query(User.email).filter_by(email=email).first()
            if not user and not email_user:
                h = (make_pw_hash(password)).split(',')
                pw_h = h[0]
                salt = h[1]
                u = User(
                    usertype = usertype,
                    username = username,
                    userpass =pw_h,
                    salt =salt,
                    email =email,
                )
                web.ctx.orm.add(u)
                cookie_user = '%s|%s' % (username,pw_h)
                #set cookie
                web.setcookie('user',cookie_user)
                self.redirect('/welcome')
            else:
                if user:
                    username_error = u'该用户名已经被使用！'
                    user=None
                if email_user:
                    email_error = u'该邮箱已经注册过，不能重复注册！'
                    email_user=None
                return self.write_html(user=user, usertype=usertype, username=username, email=email, username_error = username_error, email_error = email_error)

        else:
            username = escape_html(username)
            email = escape_html(email)
            user=None
            return self.write_html(user, usertype, username, email, username_error, password_error, v_password_error, email_error, terms_error)
            

class LoginHandler(AcountHandler):
    def write_html(self,user=None, error=''):
        return render.login(user=user, error=error)

    def GET(self):
        user = self.valid()
        return self.write_html(user)

    def POST(self):
        i = web.input()

        #username = i.username
        email = i.email
        password = i.password

        #valided_username = valid_name(username)
        valided_email = valid_email(email)
        valided_password = valid_password(password)
        
        if valided_email and valided_password:
            #validation success,access the database
            users = web.ctx.orm.query(User).filter_by(email=email).all()
            if users:
                user = users[0]
                userid = user.userid

                if verify_pw(password, user.userpass, user.salt):
                    cookie_user = '%s|%s' % (user.username, user.userpass)
                    #set cookie
                    web.setcookie('user',cookie_user)
                    self.redirect('/welcome')
            else:
                return self.write_html(user=None, error='The user is not exist,or the password does not match this acount!oops!')

        else:
            return self.write_html(user=None, error='The input name or password is invalid!oops!')

class LogoutHandler(AcountHandler):
    def GET(self):
        #delete the cookie
        web.setcookie('user','')
        self.redirect('/login')

class WelcomeHandler(AcountHandler):
    def write_html(self, user=None):
        return render.welcome(user=user)

    def GET(self):
        user = self.valid()
        if user:
            return self.write_html(user)
        else:
            self.redirect('/login')
        
class ProfileHandler(AcountHandler):
    def write_html(self,user=None,qq='',identity='',phone='',address='',family_info=None):
        return render.profile(user=user, qq=qq, identity=identity, phone=phone, address=address, family_info=family_info)

    def GET(self):
        user = self.valid()
        if user:
            profile = web.ctx.orm.query(UserProfile).filter_by(userid=user.userid).first()
            if profile:
                qq = profile.qq
                identity = profile.identity
                phone = profile.phone
                address = profile.address
                family_info = parse_family_info(profile.family_info)
                return self.write_html(user,qq,identity,phone,address,family_info)
            else:
                return self.write_html(user)
        else:
            self.redirect('/login')

class EditProfileHandler(AcountHandler):
    def write_html(self,user=None,qq='',identity='',phone='',address='',family_info=None,
            qq_error='',identity_error='',phone_error='',address_error='',family_info_error=''):
        return render.editprofile(user=user, qq=qq, identity=identity, phone=phone, address=address, family_info=family_info,
                qq_error=qq_error, identity_error=identity_error, phone_error=phone_error, address_error=address_error, family_info_error=family_info_error)

    def GET(self):
        user = self.valid()
        if user:
            userid = user.userid
            profile = web.ctx.orm.query(UserProfile).filter_by(userid=userid).first()
            print 'profile:',profile
            if profile:
                qq = profile.qq
                identity = profile.identity
                phone = profile.phone
                address = profile.address
                family_info = parse_family_info(profile.family_info)
                return self.write_html(user,qq,identity,phone,address,family_info)
            else:
                return self.write_html(user)
        else:
            self.redirect('/login')

    def POST(self):
        user = self.valid()
        if user:
            i = web.input()
            qq = i.qq
            identity = i.identity
            phone = i.phone
            address = i.address
            family_info = i.family_info

            qq_error = ''
            identity_error = ''
            phone_error = ''
            address_error = ''
            family_info_error = ''

            # check if empty then valided as True
            def valid_input(input,valid_func):
                if input =='':
                    return True
                else:
                    return valid_func(input)

            valided_qq = valid_input(qq,valid_qq)
            valided_identity = valid_input(identity,valid_identity)
            valided_phone = valid_input(phone,valid_tel)
            valided_address = valid_input(address,valid_address)
            valided_family_info = valid_input(family_info,valid_family_info)

            if not valided_qq:
                qq_error = u'您输入的QQ号有错误！'

            if not valided_identity:
                identity_error = u'您输入的身份证号有错误！'

            if not valided_phone:
                phone_error = u'您输入的手机号有错误！'

            if not valided_address:
                address_error = u'您输入的地址有错误！'

            if not valided_family_info:
                family_info_error = u'您输入的家庭信息有错误！'

            if qq_error == '' and identity_error == '' and phone_error == '' and address_error == '' and family_info_error == '':
                user_profile = web.ctx.orm.query(UserProfile).filter_by(userid=user.userid).first()
                if not user_profile:
                    user_profile = UserProfile(
                        userid = user.userid,
                        identity = identity,
                        qq = qq,
                        phone = phone,
                        address = address,
                        family_info = family_info
                    );
                    web.ctx.orm.add(user_profile)
                else:
                    user_profile.identity = identity,
                    user_profile.qq = qq,
                    user_profile.phone = phone,
                    user_profile.address = address,
                    user_profile.family_info = family_info

                self.redirect('/profile')

            else:
                print qq_error
                print identity_error
                print phone_error
                print address_error
                print family_info_error
                return self.write_html(user,qq,identity,phone,address,family_info,
                        qq_error,identity_error,phone_error,address_error,family_info_error)
        else:
            self.redirect('/login')

        

class DelAcountHandler(AcountHandler):
    def write_html(self,user=None):
        return render.delacount(user=user)

    def GET(self):
        user = self.valid()
        if user:
            return self.write_html(user)
        else:
            self.redirect('/login')

    def POST(self):
        user = self.valid()
        if user:
            i = web.input()
            delacount = i.delacount
    
            if delacount == '1':
                web.ctx.orm.delete(user)

                self.redirect('/home')
            else:
                self.redirect('/delacount')
        else:
            self.redirect('/login')











    
