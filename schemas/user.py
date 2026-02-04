# User schemas
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime
import uuid

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra='ignore')
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now())
    is_active: bool = True
    email_verified: bool = True  # Default to True since no email verification

class UserInDB(User):
    hashed_password: str
