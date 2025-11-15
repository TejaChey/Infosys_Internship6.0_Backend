import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from .db import documents_collection, kyc_data_collection, alerts_collection, audit_logs_collection, aml_blacklist_collection
from .utils import sha256_hex

# lazy imports to avoid circulars
def _verify_document_bytes(image_bytes: bytes) -> Dict[str, Any]:
    from .verification import verify_document
    return verify_document(image_bytes)

def _fraud_analyze(user: Dict[str, Any], file_bytes: bytes, parsed: Dict[str, Any], document_id: Optional[str] = None) -> Dict[str, Any]:
    from .fraud import analyze_for_fraud
    return analyze_for_fraud(user, file_bytes, parsed, document_id=document_id)

# AML rule checks
def aml_check_aadhaar(aadhaar: str) -> Dict[str, Any]:
    """
    Check AML blacklist collection for aadhaar.
    Returns dict { flagged: bool, reason: Optional[str] }
    """
    if not aadhaar:
        return {"flagged": False, "reason": None}
    entry = aml_blacklist_collection.find_one({"aadhaar": aadhaar})
    if entry:
        return {"flagged": True, "reason": "Aadhaar in AML blacklist"}
    return {"flagged": False, "reason": None}

def aml_check_address_suspicious(address: Optional[str]) -> Dict[str, Any]:
    """
    Simple AML check: if many distinct users have same address within DB -> suspicious.
    Threshold configurable; default 5 users from same address flagged.
    """
    if not address:
        return {"flagged": False, "reason": None}
    count = documents_collection.count_documents({"parsed.address": address})
    if count >= 5:
        return {"flagged": True, "reason": f"{count} documents share the same address"}
    return {"flagged": False, "reason": None}

def check_duplicate(aadhaar: Optional[str], pan: Optional[str]) -> Dict[str, Any]:
    """
    Rule-based duplicate detection across uploaded_documents.
    Returns {"duplicate": bool, "reasons": [...]}
    """
    reasons: List[str] = []
    dup = False
    if aadhaar:
        found = documents_collection.find_one({"parsed.aadhaarNumber": aadhaar})
        if found:
            dup = True
            reasons.append("Aadhaar already used")
    if pan:
        found = documents_collection.find_one({"parsed.panNumber": pan})
        if found:
            dup = True
            reasons.append("PAN already used")
    return {"duplicate": dup, "reasons": reasons}

# Alerting / Logging helpers
def add_alert(aadhaar: Optional[str], pan: Optional[str], user_email: Optional[str], risk: str, reason: str) -> Dict[str, Any]:
    alert = {
        "aadhaar": aadhaar,
        "pan": pan,
        "user": user_email,
        "risk": risk,
        "alert": reason,
        "timestamp": datetime.utcnow().isoformat(),
        "seen": False,
    }
    res = alerts_collection.insert_one(alert)
    alert["_id"] = str(res.inserted_id)
    return alert

def add_audit_log(entry: Dict[str, Any]) -> Dict[str, Any]:
    entry = dict(entry)
    entry.setdefault("createdAt", datetime.utcnow().isoformat())
    res = audit_logs_collection.insert_one(entry)
    entry["_id"] = str(res.inserted_id)
    return entry

# Full pipeline: verify -> fraud -> AML -> store -> alert if needed
def run_full_pipeline(user: Dict[str, Any], filename: str, file_bytes: bytes) -> Dict[str, Any]:
    start = time.time()
    # 1) OCR + parsing + validation
    verification = _verify_document_bytes(file_bytes)
    parsed = verification.get("parsed", {})

    # 2) store initial document record (so duplicates can be detected)
    doc_record = {
        "userId": str(user.get("_id")),
        "userEmail": user.get("email"),
        "filename": filename,
        "rawText": verification.get("rawText"),
        "parsed": parsed,
        "verification": verification,
        "createdAt": datetime.utcnow().isoformat(),
    }
    doc_id = documents_collection.insert_one(doc_record).inserted_id
    doc_record["_id"] = str(doc_id)

    # 3) fraud analysis
    fraud = _fraud_analyze(user, file_bytes, parsed, document_id=str(doc_id))

    # 4) AML checks
    aadhaar = parsed.get("aadhaarNumber")
    pan = parsed.get("panNumber")
    aml_results = []
    aad_res = aml_check_aadhaar(aadhaar)
    if aad_res["flagged"]:
        aml_results.append(aad_res["reason"])
    addr_res = aml_check_address_suspicious(parsed.get("address"))
    if addr_res["flagged"]:
        aml_results.append(addr_res["reason"])

    # 5) duplicate detection
    dup_res = check_duplicate(aadhaar, pan)
    if dup_res["duplicate"]:
        aml_results.extend(dup_res["reasons"])

    # 6) final decision logic
    score = fraud.get("score", 0)
    decision = "Pass"
    alerts: List[Dict[str, Any]] = []
    # If AML reasons or high fraud score -> Flag
    if aad_res["flagged"] or addr_res["flagged"] or dup_res["duplicate"] or score >= 71:
        decision = "Flagged"
        # create alert
        reason = "; ".join(aml_results) if aml_results else f"High fraud score {score}"
        alert = add_alert(aadhaar, pan, user.get("email"), "High" if score >= 71 else "Medium", reason)
        alerts.append(alert)
    elif score >= 31:
        decision = "Review"

    # 7) persist kyc_data snapshot
    kyc_snapshot = {
        "userId": str(user.get("_id")),
        "docId": str(doc_id),
        "docType": doc_record.get("docType"),
        "verification": verification,
        "fraud": fraud,
        "aml": {"aadhaar": aad_res, "address": addr_res, "duplicates": dup_res},
        "decision": decision,
        "alerts": [a.get("_id") for a in alerts],
        "createdAt": datetime.utcnow().isoformat(),
        "processingTimeMs": int((time.time() - start) * 1000),
    }
    kyc_data_collection.insert_one(kyc_snapshot)

    # 8) audit log
    log_entry = {
        "userId": str(user.get("_id")),
        "userEmail": user.get("email"),
        "docId": str(doc_id),
        "aadhaar": aadhaar,
        "pan": pan,
        "fraud_score": fraud.get("score"),
        "decision": decision,
    }
    add_audit_log(log_entry)

    # Return consolidated result
    return {
        "docId": str(doc_id),
        "verification": verification,
        "fraud": fraud,
        "aml_results": aml_results,
        "decision": decision,
        "alerts": alerts,
    }
