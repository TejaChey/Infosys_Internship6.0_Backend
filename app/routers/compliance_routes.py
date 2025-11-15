from fastapi import APIRouter, UploadFile, File, BackgroundTasks, HTTPException
from fastapi import Body
from typing import Optional, Dict, Any
from ..compliance import run_full_pipeline, check_duplicate, aml_check_aadhaar
from ..db import alerts_collection, audit_logs_collection, documents_collection, aml_blacklist_collection

router = APIRouter(prefix="/compliance", tags=["compliance"])

@router.post("/verify_identity")
async def verify_identity(file: UploadFile = File(...), user_email: Optional[str] = None):
    """
    Run full KYC pipeline synchronously and return result.
    """
    try:
        content = await file.read()
        user = {"_id": user_email or "anonymous", "email": user_email}
        result = run_full_pipeline(user, file.filename, content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/process_kyc")
async def process_kyc(background: BackgroundTasks, file: UploadFile = File(...), user_email: Optional[str] = None):
    """
    Start background KYC processing; returns immediately.
    """
    try:
        content = await file.read()
        user = {"_id": user_email or "anonymous", "email": user_email}
        # BackgroundTasks requires a callable with positional args
        background.add_task(run_full_pipeline, user, file.filename, content)
        return {"status": "processing"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/fraud-score/{aadhaar}")
def fraud_score_for_aadhaar(aadhaar: str):
    """
    Aggregate fraud_score for documents matching the aadhaar and return label.
    If no historical data, compute heuristic score using verhoeff, plausibility, blacklist and duplicates.
    """
    try:
        # 1) Try audit logs first
        docs = list(audit_logs_collection.find({"aadhaar": aadhaar}))
        scores = [d.get("fraud_score", 0) for d in docs if d.get("fraud_score") is not None]
        if scores:
            avg = sum(scores) / len(scores)
            label = "Low" if avg <= 30 else "Medium" if avg <= 70 else "High"
            return {"risk_score": int(avg), "risk_label": label, "source": "audit_logs"}

        # 2) No historical scores -> heuristic evaluation
        from ..verification import verhoeff_check_variants, is_plausible_aadhaar, verify_aadhaar_local

        ver = verhoeff_check_variants(aadhaar)
        plausible = is_plausible_aadhaar(aadhaar)
        local_ok = verify_aadhaar_local(aadhaar)

        details: Dict[str, Any] = {"verhoeff": ver, "plausible": plausible, "local_ok": local_ok}

        # Heuristic scoring weights (tunable)
        score = 0
        # Verhoeff failing is a strong signal
        if not ver.get("any"):
            score += 60
        else:
            # small boost if passes
            score += 0

        # Implausible numbers (obvious fakes) are strong signal
        if not plausible:
            score = min(100, score + 80)
            details["implausible"] = True
        else:
            details["implausible"] = False

        # Blacklist check
        bl = aml_blacklist_collection.find_one({"aadhaar": aadhaar})
        if bl:
            score = min(100, score + 90)
            details["blacklist"] = True
        else:
            details["blacklist"] = False

        # Duplicate documents in DB
        dup_found = documents_collection.find_one({"parsed.aadhaarNumber": aadhaar})
        if dup_found:
            score = min(100, score + 60)
            details["duplicate"] = True
        else:
            details["duplicate"] = False

        # Final normalization and label
        score = max(0, min(100, int(score)))
        label = "Low" if score <= 30 else "Medium" if score <= 70 else "High"

        return {"risk_score": score, "risk_label": label, "source": "heuristic", "details": details}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/aml/check/{aadhaar}")
def aml_check(aadhaar: str):
    try:
        res = aml_check_aadhaar(aadhaar)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/alerts")
def get_alerts():
    try:
        items = list(alerts_collection.find().sort("timestamp", -1))
        for i in items:
            i["_id"] = str(i["_id"])
        return items
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/logs/add")
def add_log(payload: Dict[str, Any] = Body(...)):
    try:
        res = audit_logs_collection.insert_one(payload)
        return {"ok": True, "id": str(res.inserted_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs")
def get_logs():
    try:
        docs = list(audit_logs_collection.find().sort("createdAt", -1))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/check-duplicate")
def check_duplicate_endpoint(payload: Dict[str, Any] = Body(...)):
    try:
        aadhaar = payload.get("aadhaar")
        pan = payload.get("pan")
        res = check_duplicate(aadhaar, pan)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
