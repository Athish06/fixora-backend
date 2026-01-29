# Email service for sending OTPs
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self, sender_email: str, app_password: str):
        self.sender_email = sender_email
        self.app_password = app_password
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        
        # In-memory OTP storage (use Redis in production)
        self.otp_store: Dict[str, Dict] = {}
    
    def generate_otp(self, length: int = 6) -> str:
        """Generate a random OTP"""
        return ''.join(random.choices(string.digits, k=length))
    
    def store_otp(self, email: str, otp: str, purpose: str = 'verification', expires_in: int = 10):
        """Store OTP with expiration (expires_in minutes)"""
        expiration = datetime.now() + timedelta(minutes=expires_in)
        self.otp_store[f"{email}:{purpose}"] = {
            'otp': otp,
            'expires_at': expiration,
            'attempts': 0
        }
        logger.info(f"OTP stored for {email} (purpose: {purpose})")
    
    def verify_otp(self, email: str, otp: str, purpose: str = 'verification') -> bool:
        """Verify OTP and check expiration"""
        key = f"{email}:{purpose}"
        stored_data = self.otp_store.get(key)
        
        if not stored_data:
            logger.warning(f"No OTP found for {email} (purpose: {purpose})")
            return False
        
        # Check expiration
        if datetime.now() > stored_data['expires_at']:
            logger.warning(f"OTP expired for {email}")
            del self.otp_store[key]
            return False
        
        # Check attempts
        if stored_data['attempts'] >= 3:
            logger.warning(f"Too many attempts for {email}")
            del self.otp_store[key]
            return False
        
        # Verify OTP
        if stored_data['otp'] == otp:
            del self.otp_store[key]  # Remove after successful verification
            logger.info(f"OTP verified successfully for {email}")
            return True
        
        # Increment attempts
        stored_data['attempts'] += 1
        logger.warning(f"Invalid OTP for {email} (attempt {stored_data['attempts']})")
        return False
    
    def send_email(self, recipient: str, subject: str, body: str) -> bool:
        """Send email using Gmail SMTP"""
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.sender_email
            message["To"] = recipient
            
            # Add HTML body
            html_part = MIMEText(body, "html")
            message.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.app_password)
                server.sendmail(self.sender_email, recipient, message.as_string())
            
            logger.info(f"Email sent successfully to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {recipient}: {str(e)}")
            return False
    
    def send_verification_otp(self, email: str, full_name: str) -> bool:
        """Send OTP for email verification"""
        otp = self.generate_otp()
        self.store_otp(email, otp, purpose='verification', expires_in=10)
        
        subject = "Verify Your Email - Fixora"
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-box {{ background: white; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #667eea; margin: 20px 0; border: 2px dashed #667eea; border-radius: 10px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Email Verification</h1>
                </div>
                <div class="content">
                    <h2>Hello {full_name}!</h2>
                    <p>Thank you for registering with Fixora. To complete your registration, please verify your email address using the OTP below:</p>
                    <div class="otp-box">{otp}</div>
                    <p><strong>This OTP will expire in 10 minutes.</strong></p>
                    <p>If you didn't request this verification, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>© 2026 Fixora - AI-Powered Vulnerability Scanning Platform</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(email, subject, body)
    
    def send_password_reset_otp(self, email: str, full_name: str) -> bool:
        """Send OTP for password reset"""
        otp = self.generate_otp()
        self.store_otp(email, otp, purpose='password_reset', expires_in=10)
        
        subject = "Reset Your Password - Fixora"
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-box {{ background: white; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #f5576c; margin: 20px 0; border: 2px dashed #f5576c; border-radius: 10px; }}
                .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset Request</h1>
                </div>
                <div class="content">
                    <h2>Hello {full_name}!</h2>
                    <p>We received a request to reset your password. Use the OTP below to proceed with resetting your password:</p>
                    <div class="otp-box">{otp}</div>
                    <p><strong>This OTP will expire in 10 minutes.</strong></p>
                    <div class="warning">
                        <strong>⚠️ Security Notice:</strong> If you didn't request a password reset, please ignore this email and ensure your account is secure.
                    </div>
                </div>
                <div class="footer">
                    <p>© 2026 Fixora - AI-Powered Vulnerability Scanning Platform</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(email, subject, body)

# Global email service instance
email_service: Optional[EmailService] = None

def get_email_service() -> EmailService:
    """Get email service instance"""
    global email_service
    if email_service is None:
        from config.settings import get_settings
        settings = get_settings()
        email_service = EmailService(
            sender_email=settings.sender_email,
            app_password=settings.google_app_password
        )
    return email_service
