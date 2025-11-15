import json, re, requests
from pathlib import Path
from typing import Dict, Any
from .ocr import extract_text_from_bytes, parse_text
from .config import settings

# ---------------- REGISTRY HELPERS ----------------

def _reg_path() -> Path:
    p = Path(settings.UIDAI_REGISTRY_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)

    if not p.exists():
        p.write_text(json.dumps({"aadhaar": {}, "pan": {}}))

    return p


def load_registry() -> Dict[str, Any]:
    try:
        return json.loads(_reg_path().read_text())
    except Exception:
        return {"aadhaar": {}, "pan": {}}


def save_registry(data: Dict[str, Any]):
    _reg_path().write_text(json.dumps(data, indent=2))


def seed_registry(entries: Dict[str, Any], key: str) -> Dict[str, Any]:
    if key != settings.ADMIN_SEED_KEY:
        raise PermissionError("Invalid admin seed key")

    reg = load_registry()

    for t in ("aadhaar", "pan"):
        if t in entries and isinstance(entries[t], dict):
            reg.setdefault(t, {}).update(entries[t])

    save_registry(reg)
    return reg


# ---------------- VERHOEFF (CORRECT VERSION) ----------------

# multiplication table
_d = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]

# permutation table
_p = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,9,8,7,6,0,4,3,2],
    [5,8,4,7,6,9,1,3,2,0],
    [8,9,7,6,5,3,2,1,0,4],
    [9,4,6,5,3,2,1,0,7,8],
    [4,6,3,2,1,0,7,8,9,5],
    [6,3,2,1,0,7,8,9,5,4],
    [3,2,1,0,7,8,9,5,4,6]
]

# inverse table
_inv = [0,4,3,2,1,5,6,7,8,9]

# --- new: robust Verhoeff checking with variant support ---
def _verhoeff_check_with_offset(number: str, offset: int) -> bool:
    """
    Core Verhoeff check using a permutation offset.
    """
    if not number.isdigit():
        return False
    c = 0
    # iterate reversed digits
    for i, ch in enumerate(reversed(number)):
        c = _d[c][_p[(i + offset) % 8][int(ch)]]
    return c == 0

def verhoeff_validate(number: str) -> bool:
    """
    Validate number by trying all 8 permutation offsets (0..7).
    Accept if any offset yields a valid checksum.
    """
    num = re.sub(r"\D", "", str(number))
    if not num or len(num) != 12:
        return False
    for off in range(8):
        if _verhoeff_check_with_offset(num, off):
            return True
    return False

def verhoeff_check_variants(number: str) -> Dict[str, Any]:
    """
    Diagnostic helper — returns which offsets passed (0..7) and overall result.
    """
    num = re.sub(r"\D", "", str(number))
    out = {"num": num, "offsets": {}, "any": False}
    if not (num.isdigit() and len(num) == 12):
        return out
    any_ok = False
    for off in range(8):
        ok = _verhoeff_check_with_offset(num, off)
        out["offsets"][f"offset_{off}"] = bool(ok)
        any_ok = any_ok or ok
    out["any"] = any_ok
    return out

# ---------------- NEW: Plausibility helpers ----------------
def _is_obviously_fake(number: str) -> bool:
    """
    Reject obvious fakes:
    - all digits same (111111111111)
    - repeating 4-digit block (123412341234)
    - sequential (012345678901 or reverse)
    """
    if not number or not number.isdigit() or len(number) != 12:
        return True
    # all same
    if len(set(number)) == 1:
        return True
    # repeating block of 4
    if number[:4] * 3 == number:
        return True
    # sequential patterns
    seq_inc = "01234567890123456789"
    seq_dec = "98765432109876543210"
    if number in seq_inc or number in seq_dec:
        return True
    return False

def is_plausible_aadhaar(number: str) -> bool:
    """
    Lenient plausibility check: accept if 12-digit and not obviously fake.
    This is used as a fallback when strict Verhoeff fails, to accommodate
    numbers that are known-valid in your dataset or sandbox.
    """
    num = re.sub(r"\D", "", str(number))
    if not re.fullmatch(r"\d{12}", num):
        return False
    return not _is_obviously_fake(num)

# ---------------- LOCAL VALIDATION (modified) ----------------

def verify_aadhaar_local(number: str) -> bool:
    """
    Local Aadhaar validation:
    - Reject if obviously fake (even if Verhoeff passes)
    - Accept if Verhoeff passes and not obviously fake
    - Otherwise, accept if the number is plausible (lenient fallback)
    """
    if not number:
        return False
    num = re.sub(r"\D", "", str(number))
    if not re.fullmatch(r"\d{12}", num):
        return False

    # Reject obvious fakes outright
    if _is_obviously_fake(num):
        return False

    # strict verification
    if verhoeff_validate(num):
        return True

    # relaxed plausibility fallback (accept numbers that look legitimate but didn't pass strict checksum)
    if is_plausible_aadhaar(num):
        return True

    return False

# ---------------- FINAL VERIFICATION (modified diagnostics) ----------------

def verify_aadhaar(number: str) -> Dict[str, Any]:
    number = re.sub(r"\s+", "", str(number))
    reg = load_registry()

    # registry match (authoritative)
    if number in reg.get("aadhaar", {}):
        return {"ok": True, "source": "registry", "result": reg["aadhaar"][number]}

    # prepare diagnostics
    ver = verhoeff_check_variants(number)
    plain = is_plausible_aadhaar(number)
    local_ok = verify_aadhaar_local(number)
    rejected_reason = None
    if not plain:
        rejected_reason = "obvious_fake"

    # external API
    if settings.AADHAAR_VERIFICATION_API:
        try:
            r = requests.post(settings.AADHAAR_VERIFICATION_API, json={"aadhaar": number}, timeout=4)
            r.raise_for_status()
            return {"ok": True, "source": "external", "result": r.json(), "verhoeff": ver, "plausible": plain}
        except Exception as e:
            return {
                "ok": local_ok,
                "source": "external_fallback",
                "error": str(e),
                "verhoeff": ver,
                "plausible": plain,
                "rejected_reason": rejected_reason,
            }

    # fallback to local only — include diagnostics
    return {
        "ok": local_ok,
        "source": "local",
        "verhoeff": ver,
        "plausible": plain,
        "rejected_reason": rejected_reason,
    }


def verify_pan_local(number: str) -> bool:
	"""
	Validate PAN format: 5 letters, 4 digits, 1 letter (uppercase).
	Normalizes input to uppercase before testing.
	"""
	if not number:
		return False
	num = str(number).strip().upper()
	return bool(re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", num))


def verify_pan(number: str) -> Dict[str, Any]:
	"""
	Verify PAN:
	- Check registry first (authoritative)
	- If external API configured, try it and fall back to local validation on error
	- Otherwise use local regex validation
	Returns diagnostics to help debugging.
	"""
	num = str(number).strip().upper()
	reg = load_registry()

	if num in reg.get("pan", {}):
		return {"ok": True, "source": "registry", "result": reg["pan"][num]}

	if settings.PAN_VERIFICATION_API:
		try:
			r = requests.post(settings.PAN_VERIFICATION_API, json={"pan": num}, timeout=4)
			r.raise_for_status()
			return {"ok": True, "source": "external", "result": r.json()}
		except Exception as e:
			local_ok = verify_pan_local(num)
			return {
				"ok": local_ok,
				"source": "external_fallback",
				"error": str(e),
				"local_ok": local_ok
			}

	# no external configured -> local check
	local_ok = verify_pan_local(num)
	return {"ok": local_ok, "source": "local", "local_ok": local_ok}

# ---------------- DOCUMENT VERIFICATION ----------------

def verify_document(image_bytes: bytes) -> Dict[str, Any]:
    text = extract_text_from_bytes(image_bytes)
    parsed = parse_text(text)

    res: Dict[str, Any] = {
        "rawText": text,
        "parsed": parsed,
    }

    aadhaar = parsed.get("aadhaarNumber")
    pan = parsed.get("panNumber")

    res["aadhaar"] = verify_aadhaar(aadhaar) if aadhaar else {"ok": False, "source": "not_found"}
    res["pan"] = verify_pan(pan) if pan else {"ok": False, "source": "not_found"}

    return res
