import time
from datetime import datetime, date
from typing import Dict, Any, Optional, List
from .db import documents_collection, kyc_data_collection, alerts_collection, audit_logs_collection, aml_blacklist_collection
from .utils import doc_type_from_parsed

# lazy import
def _verify_document_bytes(image_bytes: bytes) -> Dict[str, Any]:
    from .verification import verify_document
    from .pdf_utils import convert_pdf_to_image
    
    # Try converting PDF to image first
    converted_bytes = convert_pdf_to_image(image_bytes)
    final_bytes = converted_bytes if converted_bytes else image_bytes
    
    return verify_document(final_bytes)

def _fraud_analyze(user: Dict[str, Any], file_bytes: bytes, parsed: Dict[str, Any], document_id: Optional[str] = None, device_fingerprint: Dict[str, Any] = None, cnn_prob: float = None, gnn_prob: float = None) -> Dict[str, Any]:
    from .fraud import analyze_for_fraud
    return analyze_for_fraud(user, file_bytes, parsed, document_id=document_id, device_fingerprint=device_fingerprint, cnn_prob=cnn_prob, gnn_prob=gnn_prob)

# --- AML CHECKS ---

def aml_check_aadhaar(aadhaar: Optional[str]) -> Dict[str, Any]:
    if not aadhaar: return {"flagged": False, "reason": None}
    entry = aml_blacklist_collection.find_one({"aadhaar": aadhaar})
    if entry:
        return {"flagged": True, "reason": f"Aadhaar in AML blacklist: {entry.get('reason', 'Generic')}"}
    return {"flagged": False, "reason": None}

def aml_check_pan(pan: Optional[str]) -> Dict[str, Any]:
    if not pan: return {"flagged": False, "reason": None}
    entry = aml_blacklist_collection.find_one({"pan": pan})
    if entry:
        return {"flagged": True, "reason": f"PAN in AML blacklist: {entry.get('reason', 'Generic')}"}
    return {"flagged": False, "reason": None}

def aml_check_dl(dl: Optional[str]) -> Dict[str, Any]:
    if not dl: return {"flagged": False, "reason": None}
    entry = aml_blacklist_collection.find_one({"dl": dl})
    if entry:
        return {"flagged": True, "reason": f"DL in AML blacklist: {entry.get('reason', 'Generic')}"}
    return {"flagged": False, "reason": None}

def aml_check_age(dob: Optional[str]) -> Dict[str, Any]:
    if not dob: return {"flagged": False, "reason": None}
    try:
        sep = "-" if "-" in dob else "/"
        clean_dob = dob.strip().split()[0] 
        d, m, y = [int(x) for x in clean_dob.split(sep)]
        born = date(y, m, d)
        today = date.today()
        age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
        if age < 18:
            return {"flagged": True, "reason": f"Underage applicant ({age} years)"}
    except Exception:
        pass 
    return {"flagged": False, "reason": None}

def check_duplicate(aadhaar: Optional[str], pan: Optional[str], dl: Optional[str] = None) -> Dict[str, Any]:
    reasons: List[str] = []
    dup = False
    
    if aadhaar and documents_collection.find_one({"parsed.aadhaarNumber": aadhaar}):
        dup = True; reasons.append("Aadhaar already used")
    if pan and documents_collection.find_one({"parsed.panNumber": pan}):
        dup = True; reasons.append("PAN already used")
    if dl and documents_collection.find_one({"parsed.dlNumber": dl}):
        dup = True; reasons.append("DL already used")
        
    return {"duplicate": dup, "reasons": reasons}

def add_alert(aadhaar, pan, dl, user_email, risk, reason):
    alert = {
        "aadhaar": aadhaar, "pan": pan, "dl": dl, "user": user_email,
        "risk": risk, "alert": reason, "timestamp": datetime.utcnow().isoformat(), "seen": False
    }
    res = alerts_collection.insert_one(alert)
    alert["_id"] = str(res.inserted_id)
    return alert

# --- MAIN PIPELINE ---

def run_full_pipeline(user: Dict[str, Any], filename: str, file_bytes: bytes, device_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    start = time.time()
    
    # 0. Deep Learning Predictions (Real Integration)
    cnn_score = None
    gnn_score = None
    
    # === ENHANCED GNN: Build Duplicate Network Graph ===
    # Nodes = Users, Edges = Shared identifiers (Aadhaar, PAN, DL, email, device)
    
    graph_edges = {
        "shared_aadhaar": set(),      # Users with same Aadhaar
        "shared_pan": set(),          # Users with same PAN
        "shared_dl": set(),           # Users with same DL
        "shared_email": set(),        # Users with same email domain pattern (fraud rings)
        "shared_device": set(),       # Users from same device fingerprint
    }
    
    current_user_id = str(user.get("_id", ""))
    current_user_email = user.get("email", "")
    
    # 1. Pre-scan document for identifiers (quick OCR check)
    try:
        from .verification import verify_document
        from .pdf_utils import convert_pdf_to_image
        
        converted = convert_pdf_to_image(file_bytes)
        temp_parsed = verify_document(converted if converted else file_bytes).get("parsed", {})
        
        extracted_aadhaar = temp_parsed.get("aadhaarNumber")
        extracted_pan = temp_parsed.get("panNumber")
        extracted_dl = temp_parsed.get("dlNumber")
        
        # Check for shared Aadhaar (different users, same Aadhaar = FRAUD)
        if extracted_aadhaar:
            aadhaar_matches = documents_collection.find(
                {"parsed.aadhaarNumber": extracted_aadhaar, "userId": {"$ne": current_user_id}},
                {"userId": 1, "userEmail": 1}
            )
            for doc in aadhaar_matches:
                graph_edges["shared_aadhaar"].add(str(doc.get("userId", "")))
        
        # Check for shared PAN
        if extracted_pan:
            pan_matches = documents_collection.find(
                {"parsed.panNumber": extracted_pan, "userId": {"$ne": current_user_id}},
                {"userId": 1}
            )
            for doc in pan_matches:
                graph_edges["shared_pan"].add(str(doc.get("userId", "")))
        
        # Check for shared DL
        if extracted_dl:
            dl_matches = documents_collection.find(
                {"parsed.dlNumber": extracted_dl, "userId": {"$ne": current_user_id}},
                {"userId": 1}
            )
            for doc in dl_matches:
                graph_edges["shared_dl"].add(str(doc.get("userId", "")))
        
    except Exception as e:
        print(f"⚠️ Pre-scan for GNN edges failed: {e}")
    
    # 2. Check for shared device fingerprint
    if device_info and device_info.get("hash"):
        d_hash = device_info.get("hash")
        device_matches = documents_collection.find(
            {"deviceInfo.hash": d_hash, "userId": {"$ne": current_user_id}},
            {"userId": 1}
        )
        for doc in device_matches:
            graph_edges["shared_device"].add(str(doc.get("userId", "")))
    
    # 3. Check for same email pattern (e.g., fraud rings: user1@tempmail.com, user2@tempmail.com)
    if current_user_email and "@" in current_user_email:
        email_domain = current_user_email.split("@")[1].lower()
        suspicious_domains = ["tempmail", "guerrilla", "10minute", "throwaway", "fake", "mailinator"]
        
        if any(sus in email_domain for sus in suspicious_domains):
            # Find other users with same suspicious domain
            from .db import users_collection
            similar_emails = users_collection.find(
                {"email": {"$regex": f"@{email_domain}$", "$options": "i"}, "_id": {"$ne": user.get("_id")}},
                {"_id": 1}
            )
            for u in similar_emails:
                graph_edges["shared_email"].add(str(u.get("_id", "")))
    
    # 4. Calculate total connections for GNN
    all_connected_users = set()
    edge_weights = {
        "shared_aadhaar": 5.0,    # Highest risk - identity theft
        "shared_pan": 4.0,        # High risk - financial fraud
        "shared_dl": 3.0,         # Medium-high risk
        "shared_device": 2.0,     # Medium risk - could be shared computer
        "shared_email": 1.0,      # Lower risk - suspicious but not definitive
    }
    
    total_edge_weight = 0.0
    for edge_type, user_set in graph_edges.items():
        all_connected_users.update(user_set)
        total_edge_weight += len(user_set) * edge_weights[edge_type]
    
    connection_count = len(all_connected_users)
    
    # Calculate risk score based on edge types
    risk_score = min(1.0, total_edge_weight / 10.0)  # Normalize to 0-1
    
    try:
        from .ml_integration import predict_cnn_manipulation, predict_gnn_fraud
        
        # Run CNN
        cnn_score = predict_cnn_manipulation(file_bytes)
        
        # Run GNN (Dynamic Graph with meaningful edges)
        gnn_input = {
            "connections": connection_count,
            "risk_score": risk_score,
            "edge_types": {k: len(v) for k, v in graph_edges.items()},  # Pass edge breakdown
            "features": [
                len(graph_edges["shared_aadhaar"]),
                len(graph_edges["shared_pan"]),
                len(graph_edges["shared_dl"]),
                len(graph_edges["shared_device"]),
                len(graph_edges["shared_email"]),
                risk_score,
            ]
        }
        gnn_score = predict_gnn_fraud(gnn_input)
        
    except Exception as e:
        print(f"⚠️ ML Integration failed: {e}")

    # 1. Verification
    verification = _verify_document_bytes(file_bytes)
    parsed = verification.get("parsed", {})
    doc_type = doc_type_from_parsed(parsed)
    masked_id = verification.get("maskedAadhaar") or verification.get("maskedPan") or verification.get("maskedDl")

    # 2. Store Initial Record
    doc_record = {
        "userId": str(user.get("_id")), "userEmail": user.get("email"),
        "filename": filename, "rawText": verification.get("rawText"),
        "parsed": parsed, "verification": verification,
        "docType": doc_type, "maskedId": masked_id, "createdAt": datetime.utcnow().isoformat(),
        "deviceInfo": device_info
    }
    doc_id = documents_collection.insert_one(doc_record).inserted_id
    doc_record["_id"] = str(doc_id)

    # 3. Fraud Analysis
    fraud = _fraud_analyze(
        user, file_bytes, parsed, 
        document_id=str(doc_id), 
        device_fingerprint=device_info,
        cnn_prob=cnn_score,
        gnn_prob=gnn_score
    )
    fraud["modelVersion"] = "heuristic-v2.0 + CNN/GNN"
    documents_collection.update_one({"_id": doc_id}, {"$set": {"fraud": fraud, "fileHash": fraud.get("details", {}).get("fileHash")}})

    # 4. AML Checks
    aadhaar = parsed.get("aadhaarNumber")
    pan = parsed.get("panNumber")
    dl = parsed.get("dlNumber")
    
    aml_results = []
    
    # Run individual checks
    checks = [
        aml_check_aadhaar(aadhaar),
        aml_check_pan(pan),
        aml_check_dl(dl),
        aml_check_age(parsed.get("dob"))
    ]
    for c in checks:
        if c["flagged"]: aml_results.append(c["reason"])

    # 5. Duplicate Check
    dup_res = check_duplicate(aadhaar, pan, dl)
    if dup_res["duplicate"]: aml_results.extend(dup_res["reasons"])

    # 6. Final Decision
    score = fraud.get("score", 0)
    decision = "Pass"
    alerts = []
    
    if aml_results or score >= 71:
        decision = "Flagged"
        reason = "; ".join(aml_results) if aml_results else f"High fraud score {score}"
        alert = add_alert(aadhaar, pan, dl, user.get("email"), "High" if score >= 71 else "Medium", reason)
        alerts.append(alert)
    elif score >= 31:
        decision = "Review"

    # 7. Snapshot & Log
    kyc_snapshot = {
        "userId": str(user.get("_id")), "docId": str(doc_id), "docType": doc_type,
        "verification": verification, "fraud": fraud, "aml_results": aml_results,
        "decision": decision, "alerts": [a.get("_id") for a in alerts], "userEmail": user.get("email"),
        "createdAt": datetime.utcnow().isoformat(), "processingTimeMs": int((time.time() - start) * 1000)
    }
    kyc_data_collection.insert_one(kyc_snapshot)

    audit_logs_collection.insert_one({
        "userId": str(user.get("_id")), "docId": str(doc_id),
        "aadhaar": aadhaar, "pan": pan, "dl": dl,
        "decision": decision, "createdAt": datetime.utcnow().isoformat(),
        "deviceInfo": device_info
    })

    return {
        "docId": str(doc_id), "verification": verification,
        "fraud": fraud, "aml_results": aml_results, "decision": decision, "alerts": alerts
    }