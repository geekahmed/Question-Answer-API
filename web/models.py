import os
from sqlalchemy import Column, String, Integer, create_engine, ForeignKey, DateTime
from flask_sqlalchemy import SQLAlchemy
import json
import datetime


db = SQLAlchemy()
def setup_db(app, database_path):
    db.app = app
    db.init_app(app)
    db.create_all()

class Question(db.Model):
    __tablename__ = 'questions'

    id = Column(Integer, primary_key=True)
    title = Column(String)
    content = Column(String)
    uid = Column(Integer, ForeignKey('users.id'))

    def __init__(self, title, content, uid):
        self.title = title
        self.content = content
        self.uid = uid
   
    def insert(self):
        db.session.add(self)
        db.session.commit()
    
    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def format(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'user_id': self.uid
        }


class Answer(db.Model):
    __tablename__ = 'answers'

    id = Column(Integer, primary_key=True)
    content = Column(String)
    uid = Column(Integer, ForeignKey('users.id'))
    qid = Column(Integer, ForeignKey('questions.id'))
    def __init__(self, content, uid, qid):
        self.content = content
        self.uid = uid
        self.qid = qid

   
    def insert(self):
        db.session.add(self)
        db.session.commit()
        
    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def format(self):
        return {
            'id': self.id,
            'content': self.content,
            'user_id': self.uid,
            'question_id': self.qid
        }


class User(db.Model):
    __tablename__ = 'users'

    id = Column(Integer, primary_key = True, autoincrement=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String(255), nullable=False)

    def __init__(self, first_name, last_name, email, password):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
   
    def insert(self):
        db.session.add(self)
        db.session.commit()
     
    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email
         }



class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(500), unique=True, nullable=False)
    blacklisted_on = Column(DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)
    def insert(self):
        db.session.add(self)
        db.session.commit()
     
    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False