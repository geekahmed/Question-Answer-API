import os
import unittest
import json
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from models import setup_db, Question, Answer, User
from app import app


class qaTestCases(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client
        self.database_name = "qa"
        self.database_path = "postgres://postgres:ahmed@{}/{}".format('localhost:5432', self.database_name)
        setup_db(self.app, self.database_path)
        with self.app.app_context():
            self.db = SQLAlchemy()
            self.db.init_app(self.app)
            # create all tables
            self.db.create_all()
    def tearDown(self):
        """Executed after reach test"""
        pass

    def test_get_home(self):
        res = self.client().get('/')
        data = json.loads(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(data['success'], True)
        self.assertTrue(len(data['questions']))
        




# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()