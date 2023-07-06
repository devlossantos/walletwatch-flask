import os

class Config:
    SECRET_KEY = 'cctcollege'
    MYSQL_HOST = os.environ['MYSQL_HOST']
    MYSQL_PORT = int(os.environ['MYSQL_PORT'])
    MYSQL_USER = os.environ['MYSQL_USER']
    MYSQL_PASSWORD = os.environ['MYSQL_PASSWORD']
    MYSQL_DB = os.environ['MYSQL_DATABASE']

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

def get_config():
    if os.environ.get('FLASK_ENV') == 'production':
        return ProductionConfig
    else:
        return DevelopmentConfig
