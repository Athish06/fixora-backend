# Authentication routes
from fastapi import APIRouter, Depends, HTTPException, status
from config.database import get_database
from middleware.auth import get_current_user
from utils.password import get_password_hash, verify_password
from utils.jwt import create_access_token, Token, TokenData
from utils.encryption import encrypt_api_key
from schemas.user import User, UserCreate, UserLogin, UserInDB, GroqKeyUpdate

router = APIRouter(prefix='/auth', tags=['Authentication'])

@router.post('/register', status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db = Depends(get_database)):
    """Register a new user"""
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
        email_verified=True  # Auto-verify since no email verification
    )
    
    doc = user_in_db.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    
    await db.users.insert_one(doc)
    
    return {
        'message': 'Registration successful. You can now login.',
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
    # Dynamically compute has_groq_key from the stored encrypted field
    user_doc['has_groq_key'] = bool(user_doc.get('encrypted_groq_key'))
    return User(**user_doc)


# ── GROQ API KEY MANAGEMENT ─────────────────────────────────────────────────

@router.put('/groq-key')
async def save_groq_key(
    body: GroqKeyUpdate,
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Save or update the user's Groq API key (encrypted at rest)."""
    raw_key = body.api_key.strip()

    # Validate Groq key format
    if not raw_key.startswith('gsk_'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid Groq API key. It must start with "gsk_". Get one free at console.groq.com'
        )

    # Encrypt and store
    encrypted = encrypt_api_key(raw_key)
    result = await db.users.update_one(
        {'id': current_user.user_id},
        {'$set': {'encrypted_groq_key': encrypted}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')

    return {'message': 'Groq API key saved securely', 'has_groq_key': True}


@router.delete('/groq-key')
async def delete_groq_key(
    current_user: TokenData = Depends(get_current_user),
    db = Depends(get_database)
):
    """Remove the user's stored Groq API key."""
    result = await db.users.update_one(
        {'id': current_user.user_id},
        {'$unset': {'encrypted_groq_key': ''}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')

    return {'message': 'Groq API key removed', 'has_groq_key': False}
