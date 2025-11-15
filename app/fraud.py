import io
import hashlib
from typing import Dict, Any
from PIL import Image, UnidentifiedImageError
from rapidfuzz import fuzz
from .db import documents_collection
import numpy as np

# Try to import cv2 for a robust Laplacian-based sharpness check; fall back gracefully.
try:
    import cv2
except Exception:
    cv2 = None

# Weights for heuristics; tune as needed.
_WEIGHTS = {
    "aadhaar_invalid": 40,
    "pan_invalid": 30,
    "duplicate": 20,
    "manipulation": 10,
    "name_mismatch": 10,
}

def _is_duplicate(file_hash: str, parsed: Dict[str, Any], user_id: str) -> bool:
    # duplicate by file hash (any document except same id) OR by Aadhaar/PAN used by other users
    if documents_collection.find_one({"fileHash": file_hash}):
        return True
    aid = parsed.get("aadhaarNumber")
    pan = parsed.get("panNumber")
    q = []
    if aid: q.append({"parsed.aadhaarNumber": aid})
    if pan: q.append({"parsed.panNumber": pan})
    if q and documents_collection.find_one({"$or": q, "userId": {"$ne": str(user_id)}}):
        return True
    return False

def _compute_sharpness_cv2(gray: np.ndarray) -> float:
    # Laplacian variance is a common measure for blur: higher -> sharper
    lap = cv2.Laplacian(gray, cv2.CV_64F)
    return float(lap.var())

def _compute_sharpness_fallback(gray: np.ndarray) -> float:
    # Approximate by variance of gradients (numpy)
    gx = np.diff(gray, axis=1)
    gy = np.diff(gray, axis=0)
    grad = np.concatenate([gx.flatten(), gy.flatten()]) if gx.size + gy.size > 0 else np.array([0.0])
    return float(np.var(grad))

def _detect_manipulation(file_bytes: bytes) -> bool:
    try:
        img = Image.open(io.BytesIO(file_bytes))
        exif = getattr(img, "_getexif", lambda: None)()
        if not exif:
            return True
        return False
    except UnidentifiedImageError:
        return True
    except Exception:
        return True

def analyze_for_fraud(user: Dict[str, Any], file_bytes: bytes, parsed: Dict[str, Any], document_id: str | None = None) -> Dict[str, Any]:
    details: Dict[str, Any] = {}
    score = 0.0

    # compute sha256 locally
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    details["fileHash"] = file_hash

    # Local validations (lazy import to avoid circular import at module load)
    from . import verification as _verification

    aadhaar = parsed.get("aadhaarNumber")
    if aadhaar is not None:
        ok = _verification.verify_aadhaar_local(aadhaar)
        details["aadhaar_valid_local"] = ok
        if not ok: score += _WEIGHTS["aadhaar_invalid"]
    pan = parsed.get("panNumber")
    if pan is not None:
        okp = _verification.verify_pan_local(pan)
        details["pan_valid_local"] = okp
        if not okp: score += _WEIGHTS["pan_invalid"]

    # Duplicate
    is_dup = _is_duplicate(file_hash, parsed, str(user.get("_id")))
    details["duplicate"] = is_dup
    if is_dup: score += _WEIGHTS["duplicate"]

    # Manipulation
    manipulated = _detect_manipulation(file_bytes)
    details["manipulation_suspected"] = manipulated
    if manipulated: score += _WEIGHTS["manipulation"]

    # Name match vs user profile name (if both present)
    if user.get("name") and parsed.get("name"):
        match = int(fuzz.token_set_ratio(str(user["name"]).upper(), str(parsed["name"]).upper()))
        details["name_match_pct"] = match
        if match < 80:
            score += _WEIGHTS["name_mismatch"]
    else:
        details["name_match_pct"] = None

    score = max(0.0, min(100.0, score))
    band = "Low" if score <= 30 else "Medium" if score <= 70 else "High"
    return {"score": score, "band": band, "details": details}
