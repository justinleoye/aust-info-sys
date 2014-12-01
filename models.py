#!/usr/bin/env python
#-*- coding: utf-8 -*-
import web

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String , Text , DateTime


Base = declarative_base()

class User(Base):
    __tablename__='user'

    userid = Column(Integer, primary_key = True)
    usertype = Column(String(20))
    username = Column(String(20))
    userpass = Column(String(100))
    salt = Column(String(100))
    email = Column(String(100))

class UserProfile(Base):
    __tablename__='user_profile'

    userid = Column(Integer, primary_key = True)
    identity = Column(String(20))    
    qq = Column(String(20))    
    phone = Column(String(20))    
    address = Column(String(200))    
    family_info = Column(Text) # a stringified json object

class Action(Base):
    __tablename__='action'

    id = Column(Integer, primary_key = True)
    name = Column(String(20))
    action = Column(String(100))

class Role(Base):
    __tablename__='role'
    id = Column(Integer, primary_key = True)
    name = Column(String(20))
    actionid = Column(Integer)

class UserRole(Base):
    __tablename__='user_role'
    id = Column(Integer, primary_key = True)
    userid = Column(Integer)
    roleid = Column(Integer)
    status = Column(String(20))
