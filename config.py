# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-change-in-production'
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///chatapp.db')
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///chat.db'
    SQLALCHEMY_DATABASE_URI = postgresql://grp_chat_db_user:hIYLyVW936DWfcCxwYAAKHndkzad9tVk@dpg-d46h4t3ipnbc73dh12t0-a/grp_chat_db
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # Verify connections before using
        'pool_recycle': 300,     # Recycle connections after 5 minutes
    }
    
    # Session configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # AI Configuration
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = postgresql://grp_chat_db_user:hIYLyVW936DWfcCxwYAAKHndkzad9tVk@dpg-d46h4t3ipnbc73dh12t0-a/grp_chat_db

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # HTTPS only


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig

}
