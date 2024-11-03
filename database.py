from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
import logging
import time
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

class RetryingDatabase(SQLAlchemy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_retries = 5
        self.initial_backoff = 1  # seconds

    def connect_with_retry(self, app):
        """Attempts to establish database connection with exponential backoff"""
        retry_count = 0
        last_error = None
        backoff = self.initial_backoff

        # Configure database URL with SSL requirements
        db_url = os.getenv('DATABASE_URL')
        if '?' not in db_url:
            db_url += '?'
        else:
            db_url += '&'
        db_url += 'sslmode=require'

        # Configure the SQLAlchemy engine with pool settings
        app.config['SQLALCHEMY_DATABASE_URI'] = db_url
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': 5,
            'max_overflow': 10,
            'pool_timeout': 30,
            'pool_recycle': 1800,
            'pool_pre_ping': True,
            'connect_args': {
                'sslmode': 'require',
                'connect_timeout': 10
            }
        }

        # Initialize the app
        self.init_app(app)

        while retry_count < self.max_retries:
            try:
                with app.app_context():
                    # Test the connection using proper SQLAlchemy syntax
                    with self.engine.connect() as conn:
                        conn.execute(text("SELECT 1"))
                        conn.commit()
                    logger.info("Successfully established database connection")
                    return True

            except OperationalError as e:
                last_error = e
                retry_count += 1
                logger.error(f"Database connection attempt {retry_count} failed: {str(e)}")
                
                if retry_count < self.max_retries:
                    logger.info(f"Retrying in {backoff} seconds...")
                    time.sleep(backoff)
                    backoff *= 2  # Exponential backoff
                else:
                    logger.error("Max retries reached. Could not establish database connection.")
                    raise Exception(f"Failed to connect to database after {self.max_retries} attempts. Last error: {str(last_error)}")

            except SQLAlchemyError as e:
                logger.error(f"SQLAlchemy error during connection: {str(e)}")
                raise

            except Exception as e:
                logger.error(f"Unexpected error during database connection: {str(e)}")
                raise

db = RetryingDatabase(model_class=Base)
