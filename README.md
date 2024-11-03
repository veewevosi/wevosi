# WEVOSI - Property & Construction Platform

A dark-themed web application with user authentication built using Flask and Vanilla JS. WEVOSI connects sellers with buyers and facilitates building construction with engineered intelligence.

## Features

- User Authentication (Signup/Login)
- Email Verification
- Password Reset Functionality
- Profile Management
- Dark Theme UI
- Profile Picture Upload
- User Settings
- Dashboard Interface

## Tech Stack

- Backend: Flask (Python)
- Frontend: Vanilla JavaScript, HTML5, CSS3
- Database: PostgreSQL
- Email Service: SendGrid
- File Storage: Local Storage with PIL for image processing

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up environment variables:
   - DATABASE_URL
   - SENDGRID_API_KEY
   - SENDGRID_VERIFIED_SENDER
   - SECRET_KEY

4. Run the application:
   ```bash
   python app.py
   ```

## License

MIT License
