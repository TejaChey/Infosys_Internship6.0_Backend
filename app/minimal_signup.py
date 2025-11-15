import hashlib
from datetime import datetime
from typing import Dict
from urllib.parse import parse_qs

from passlib.context import CryptContext
from .db import users_collection

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def _hash_password(password: str) -> str:
	# truncate to 72 bytes (bcrypt limit)
	pw_bytes = (password or "").encode("utf-8")[:72]
	pw_safe = pw_bytes.decode("utf-8", "ignore")
	return pwd_context.hash(pw_safe)

def signup_direct_from_form_bytes(body_bytes: bytes) -> Dict:
	"""
	Parse application/x-www-form-urlencoded body bytes, create user.
	Returns dict with either {'ok': True, 'id': str} or {'ok': False, 'error': '...'}
	"""
	try:
		data = parse_qs(body_bytes.decode("utf-8", "ignore"))
		name = data.get("name", [""])[0]
		email = data.get("email", [""])[0]
		password = data.get("password", [""])[0]
		if not email or not password:
			return {"ok": False, "error": "email and password are required"}
		# simple duplicate check
		if users_collection.find_one({"email": email}):
			return {"ok": False, "error": "Email already registered"}
		hashed = _hash_password(password)
		doc = {
			"name": name,
			"email": email,
			"password": hashed,
			"createdAt": datetime.utcnow().isoformat()
		}
		res = users_collection.insert_one(doc)
		return {"ok": True, "id": str(res.inserted_id), "email": email}
	except Exception as e:
		return {"ok": False, "error": str(e)}
