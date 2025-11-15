from fastapi import APIRouter, HTTPException, Header, Query, File, UploadFile, Depends, Body
from typing import Optional
from ..verification import verify_aadhaar, verify_pan, seed_registry, load_registry, verhoeff_check_variants
from ..config import settings
from ..upload import process_upload
from ..security import get_current_user

router = APIRouter(prefix="/verify", tags=["verification"])

@router.get("/aadhaar/{number}")
def aadhaar_check(number: str):
    try:
        return verify_aadhaar(number)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/pan/{number}")
def pan_check(number: str):
    try:
        return verify_pan(number)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/dev/seed")
def dev_seed(payload: dict = Body(...), seed_key: Optional[str] = Query(None), x_seed_key: Optional[str] = Header(None)):
    provided = seed_key or x_seed_key
    if not provided or provided != settings.ADMIN_SEED_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing admin seed key")
    try:
        return {"message": "seeded", "registry": seed_registry(payload, provided)}
    except PermissionError:
        raise HTTPException(status_code=403, detail="Invalid admin seed key")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dev/registry")
def get_registry(seed_key: Optional[str] = Query(None), x_seed_key: Optional[str] = Header(None)):
    provided = seed_key or x_seed_key
    if not provided or provided != settings.ADMIN_SEED_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing admin seed key")
    return load_registry()

@router.post("/verify-doc")
async def verify_doc(file: UploadFile = File(...), current_user = Depends(get_current_user)):
    try:
        content = await file.read()
        record = process_upload(current_user, file.filename, content)
        return {"docId": record["_id"], "verification": record.get("verification"), "fraud": record.get("fraud")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/debug/verhoeff/{number}", summary="Debug Verhoeff offsets for Aadhaar")
def debug_verhoeff(number: str):
    """
    Returns which Verhoeff permutation offsets (0..7) validate the provided 12-digit number.
    Useful to debug why a number is failing local validation.
    """
    try:
        return verhoeff_check_variants(number)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
