import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ["SECRET_KEY"]
    user = os.environ["POSTGRES_USER"]
    password = os.environ["POSTGRES_PASSWORD"]
    hostname = os.environ["POSTGRES_HOSTNAME"]
    port = 5432
    database = os.environ["APPLICATION_DB"]
    SQLALCHEMY_DATABASE_URI = (
        f"postgres://{user}:{password}@{hostname}:{port}/{database}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProductionConfig(Config):
    

class DevelopmentConfig(Config):
  

class TestingConfig(Config):
    TESTING = True
