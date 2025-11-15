from fastapi import APIRouter, Form, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from ..models import UserCreate, Token
from ..auth import signup_user, authenticate_user

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/signup", response_model=Token)
def signup(name: str = Form(None), email: str = Form(...), password: str = Form(...)):
	# defensive: truncate password to 72 bytes before any processing (bcrypt limit)
	raw_pw = password or ""
	pw_bytes = raw_pw.encode("utf-8")[:72]
	pw = pw_bytes.decode("utf-8", "ignore")
	user_in = UserCreate(name=name, email=email, password=pw)
	try:
		signup_user(user_in)
	except HTTPException:
		raise
	except Exception as e:
		raise HTTPException(status_code=400, detail=str(e))
	# auto-login after signup
	token = authenticate_user(email, pw)
	if not token:
		raise HTTPException(status_code=400, detail="Could not create token")
	return {"access_token": token, "token_type": "bearer"}

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
	token = authenticate_user(form_data.username, form_data.password)
	if not token:
		raise HTTPException(status_code=401, detail="Invalid credentials")
	return {"access_token": token, "token_type": "bearer"}
