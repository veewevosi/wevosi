from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
import logging

logger = logging.getLogger(__name__)

def send_verification_email(user_email, verification_url):
    """Send verification email using SendGrid."""
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        message = Mail(
            from_email=os.environ.get('SENDGRID_VERIFIED_SENDER'),
            to_emails=user_email,
            subject='WEVOSI - Verify Your Email Address',
            html_content=f'''
                <h2>Welcome to WEVOSI!</h2>
                <p>Thank you for signing up. Please click the link below to verify your email address:</p>
                <p><a href="{verification_url}">Verify Email Address</a></p>
                <p>If you did not create an account, you can safely ignore this email.</p>
                <p>Best regards,<br>The WEVOSI Team</p>
            '''
        )
        response = sg.send(message)
        logger.info(f"Verification email sent to {user_email}, status code: {response.status_code}")
        return True
    except Exception as e:
        logger.error(f"Failed to send verification email to {user_email}: {str(e)}")
        return False

def send_password_reset_email(user_email, reset_url):
    """Send password reset email using SendGrid."""
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        message = Mail(
            from_email=os.environ.get('SENDGRID_VERIFIED_SENDER'),
            to_emails=user_email,
            subject='WEVOSI - Password Reset Request',
            html_content=f'''
                <h2>Password Reset Request</h2>
                <p>You have requested to reset your password. Click the link below to proceed:</p>
                <p><a href="{reset_url}">Reset Password</a></p>
                <p>If you did not request this password reset, you can safely ignore this email.</p>
                <p>Best regards,<br>The WEVOSI Team</p>
            '''
        )
        response = sg.send(message)
        logger.info(f"Password reset email sent to {user_email}, status code: {response.status_code}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user_email}: {str(e)}")
        return False
