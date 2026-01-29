# Authentication routes
from fastapi import APIRouter, Depends, HTTPException, status
from config.database import get_database
from middleware.auth import get_current_user
from utils.password import get_password_hash, verify_password
from utils.jwt import create_access_token, Token, TokenData
from schemas.user import User, UserCreate, UserLogin, UserInDB, OTPVerify, ResendOTP, ForgotPassword, ResetPassword
from services.email_service import get_email_service

router = APIRouter(prefix='/auth', tags=['Authentication'])

@router.post('/register', status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db = Depends(get_database)):
    """Register a new user and send verification OTP"""
    # Check if user exists
    existing_user = await db.users.find_one({'email': user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Email already registered'
        )
    
    # Create user
    user_dict = user_data.model_dump()
    hashed_password = get_password_hash(user_dict.pop('password'))
    
    user_in_db = UserInDB(
        **user_dict,
        hashed_password=hashed_password,
        email_verified=False
    )
    
    doc = user_in_db.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.users.insert_one(doc)
    
    # Send verification OTP
    email_service = get_email_service()
    if not email_service.send_verification_otp(user_in_db.email, user_in_db.full_name):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to send verification email'
        )
    
    return {
        'message': 'Registration successful. Please check your email for verification OTP.',
        'email': user_in_db.email
    }

@router.post('/login', response_model=Token)
async def login(credentials: UserLogin, db = Depends(get_database)):
    """Login with email and password"""
    # Find user
    user_doc = await db.users.find_one({'email': credentials.email})
    if not user_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid credentials'
        )
    
    user_in_db = UserInDB(**user_doc)
    
    # Verify password
    if not verify_password(credentials.password, user_in_db.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid credentials'
        )
    
    # Create access token
    access_token = create_access_token(
        data={'sub': user_in_db.id, 'email': user_in_db.email}
    )
    
    return Token(access_token=access_token)

@router.get('/me', response_model=User)
async def get_me(current_user: TokenData = Depends(get_current_user), db = Depends(get_database)):
    """Get current user information"""
    user_doc = await db.users.find_one({'id': current_user.user_id}, {'_id': 0})
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    return User(**user_doc)

@router.post('/verify-email', response_model=Token)
async def verify_email(otp_data: OTPVerify, db = Depends(get_database)):
    """Verify email with OTP"""
    email_service = get_email_service()
    
    # Verify OTP
    if not email_service.verify_otp(otp_data.email, otp_data.otp, purpose='verification'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid or expired OTP'
        )
    
    # Update user email_verified status
    result = await db.users.update_one(
        {'email': otp_data.email},
        {'$set': {'email_verified': True}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User not found'
        )
    
    # Get user and create token
    user_doc = await db.users.find_one({'email': otp_data.email})
    user = UserInDB(**user_doc)
    
    # Create access token
    access_token = create_access_token(
        data={'sub': user.id, 'email': user.email}
    )
    
    return Token(access_token=access_token)

@router.post('/resend-otp')
async def resend_otp(data: ResendOTP, db = Depends(get_database)):
    """Resend verification OTP"""
    # Check if user exists
    user_doc = await db.users.find_one({'email': data.email})
    if not user_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User not found'
        )
    
    user = User(**user_doc)
    
    # Check if already verified
    if user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Email already verified'
        )
    
    # Send OTP
    email_service = get_email_service()
    if not email_service.send_verification_otp(user.email, user.full_name):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to send verification email'
        )
    
    return {'message': 'Verification OTP sent successfully'}

@router.post('/forgot-password')
async def forgot_password(data: ForgotPassword, db = Depends(get_database)):
    """Request password reset OTP"""
    # Check if user exists
    user_doc = await db.users.find_one({'email': data.email})
    if not user_doc:
        # Don't reveal if email exists or not for security
        return {'message': 'If the email exists, a password reset OTP has been sent'}
    
    user = User(**user_doc)
    
    # Send password reset OTP
    email_service = get_email_service()
    if not email_service.send_password_reset_otp(user.email, user.full_name):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to send password reset email'
        )
    
    return {'message': 'If the email exists, a password reset OTP has been sent'}

@router.post('/reset-password')
async def reset_password(data: ResetPassword, db = Depends(get_database)):
    """Reset password with OTP"""
    email_service = get_email_service()
    
    # Verify OTP
    if not email_service.verify_otp(data.email, data.otp, purpose='password_reset'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid or expired OTP'
        )
    
    # Update password
    hashed_password = get_password_hash(data.new_password)
    result = await db.users.update_one(
        {'email': data.email},
        {'$set': {'hashed_password': hashed_password}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User not found'
        )
    
    return {'message': 'Password reset successfully'}
