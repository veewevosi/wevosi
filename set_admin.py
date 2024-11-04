from app import app, db
from models import User
import logging
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def set_admin():
    with app.app_context():
        try:
            # Add role column if it doesn't exist using proper SQLAlchemy text()
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT \'user\''))
            db.session.commit()
            logger.info("Added role column to user table")

            # Set mike@wevosi.com as admin
            user = User.query.filter_by(email='mike@wevosi.com').first()
            if user:
                user.role = 'admin'
                db.session.commit()
                logger.info(f"Set user {user.email} as admin")
            else:
                logger.warning("User mike@wevosi.com not found")

        except Exception as e:
            logger.error(f"Error setting admin: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    set_admin()
