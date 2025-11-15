from datetime import datetime
from fastapi import HTTPException, status
from .db import users_collection
from .models import UserCreate
from .security import hash_password, verify_password, create_access_token

def signup_user(user_in: UserCreate):
    # 1. Check if user already exists
    existing = users_collection.find_one({"email": user_in.email})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # 2. Bcrypt allows only first 72 bytes → safely truncate BEFORE hashing
    raw_password = user_in.password or ""
    pw_bytes = raw_password.encode("utf-8")[:72]         # truncate to bcrypt-safe range

    # Decode ONLY for our hash_password function (ignore invalid UTF-8 after truncation)
    pw_safe = pw_bytes.decode("utf-8", errors="ignore")

    # 3. Insert clean user object
    user_doc = {
        "name": user_in.name.strip(),
        "email": user_in.email.lower().strip(),
        "password": hash_password(pw_safe),             # hash it
        "createdAt": datetime.utcnow(),
    }

    result = users_collection.insert_one(user_doc)

    # 4. Return sanitized response (NEVER return password)
    return {
        "id": str(result.inserted_id),
        "email": user_in.email,
        "message": "User created successfully"
    }


def authenticate_user(email: str, password: str):
	user = users_collection.find_one({"email": email})
	if not user:
		return None
	hashed = user.get("password") or user.get("hashed_password")
	# if verify_password expects hashed (passlib) it'll work; adapt if different
	if not hashed or not verify_password(password, hashed):
		return None
	# create token with subject as email
	token = create_access_token({"sub": user["email"]})
	return token
