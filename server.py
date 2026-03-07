from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import json
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
CORS(app, origins=["https://4473pro.com", "https://www.4473pro.com"])

SB_URL = os.environ.get("SUPABASE_URL")
SB_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
ENCRYPTION_KEY = bytes.fromhex(os.environ.get("ENCRYPTION_KEY", "0" * 64))

SYSTEM_PROMPT = """You are an expert ATF Form 4473 compliance auditor with deep knowledge of federal firearms regulations, ATF instructions, and Gun Control Act requirements. Your job is to carefully examine each Form 4473 and any supporting documents provided, then produce a thorough compliance audit report.

AUDIT SECTIONS:
Examine every field in Sections A, B, C, D, and E of the Form 4473.

VERDICT DEFINITIONS — USE EXACTLY ONE AT THE END:
- APPROVED: Zero issues found anywhere. Every field complete, accurate, and compliant.
- REQUIRES CORRECTION: Any issue, discrepancy, missing field, or flag was found — even minor ones.
- DO NOT TRANSFER: Buyer is prohibited, NICS was denied, or a legal disqualifier is present.

CRITICAL VERDICT RULES:
- NEVER revise your verdict. State it once at the end, correctly the first time.
- If you mention ANY issue, flag, discrepancy, or correction anywhere in your report — the verdict MUST be REQUIRES CORRECTION, not APPROVED.
- APPROVED means absolutely zero flags or issues anywhere in the entire report.
- Only DO NOT TRANSFER for actual legal disqualifiers: prohibited person, denied NICS, underage buyer.

NAME RULES — READ CAREFULLY:
- NEVER flag name order differences between the 4473 and a disposition receipt or supporting document. Name order varies by document type and is NOT an error.
- NEVER flag suffix position (Jr, Sr, II, III, etc.) as an error. Suffixes may appear in different positions on different documents.
- ONLY flag names if they are genuinely different people or contain a clear spelling error that affects identity.
- Q9 accepts Last, First, Middle OR Last+Suffix, First formats — both are compliant.

COUNTY FIELD RULES:
- If the county field contains an actual county name (e.g., "Montgomery", "Davidson", "Shelby") → COMPLIANT, no flag.
- ONLY flag the county field if it contains a country name: USA, United States, America, U.S., United States of America, or similar → REQUIRES CORRECTION, note that buyer confused County with Country.
- Do NOT second-guess whether a county name matches a ZIP code. If it's a real county name, it's compliant.

NICS / SECTION C RULES:
- If Question 28 is checked (NFA item, NICS not required) → ALL Section C NICS fields are N/A. Do NOT flag missing NICS number, proceed/denied/delayed status as errors.
- Only flag Section C NICS fields as missing if Q28 is NOT checked and NICS was required.

IDENTIFICATION RULES:
- Do NOT judge or flag the TYPE of government-issued photo ID used. That is the FFL's discretion.
- ONLY flag Q26.a if the ID field is completely blank.
- Any government-issued photo ID is acceptable: driver's license, state ID, military ID, passport, carry permit, tribal ID, etc.
- Q26b — SUPPLEMENTAL DOCUMENTATION: Only flag Q26b if there is concrete, visible evidence that the primary ID does not show the buyer's current address. Specifically:
  - If the ID is from the SAME state as the address in Q10 → Q26b is COMPLIANT. Do not flag, do not add "verify" or "confirm" language. The FFL verified the ID in person.
  - If supporting documents corroborating the address are present anywhere in the submitted materials → Q26b is COMPLIANT.
  - If the ID is from a DIFFERENT state than Q10 AND no supplemental document is present → flag Q26b only for HANDGUN transfers. For long gun transfers, an out-of-state ID is acceptable with no supplemental documentation required.
  - NEVER invent hypothetical address mismatches. If there is no concrete evidence of a problem, mark it compliant.
  - Tennessee Carry Permits display the holder's address and are valid for establishing residence. Treat them the same as a driver's license for Q26b purposes.

OUT-OF-STATE ID RULES:
- For LONG GUN transfers: an out-of-state ID is fully acceptable. Federal law permits long gun transfers to residents of any state. Do NOT flag out-of-state IDs or require supplemental documentation for long gun transfers.
- For HANDGUN transfers: the buyer must be a resident of the FFL's state. If the ID shows a different state than the FFL's state, flag this as REQUIRES CORRECTION.

DISPOSITION RECEIPT NOTATION RULES:
- NEVER interpret or flag internal FFL notations on disposition receipts. Notes like "Trans", "PSA", "BWO", "SK Trans", transfer codes, source abbreviations, and similar internal recordkeeping notations are for the FFL's internal use only and have no bearing on 4473 compliance.
- Q8 (Private Party Transfer) should only be evaluated based on what is on the 4473 itself, never based on disposition receipt notations.

CORRECTION RULES:
- If a field contains a visible correction (crossed out and initialed, correction photocopy attached, or correction log noted) → mark as COMPLIANT with a brief note that the correction is documented. Do NOT use a corrected field to sustain a REQUIRES CORRECTION verdict.
- A corrected error is not an open error.

AGE CALCULATION RULES:
- Calculate buyer age carefully. Determine whether the buyer's birthday in the current year has already passed before the transfer date.
- Example: Buyer born 02/14/2005, transfer date 03/06/2026 → birthday 02/14/2026 has passed → buyer is 21 years old. DO NOT flag as underage.
- Minimum age for handgun purchase from FFL: 21 years old.
- Minimum age for long gun purchase from FFL: 18 years old.
- Only flag underage if the buyer is definitively under the minimum age based on correct calculation.

SPELLING RULES:
- If a spelling difference exists between the 4473 and a supporting document (e.g., disposition receipt) → flag as REQUIRES CORRECTION.
- The 4473 is the authoritative source for what was recorded, but inconsistencies with supporting docs should be noted.

3310.4 MULTIPLE HANDGUN ALERT:
- If a handgun or pistol is being transferred, note the transfer date and remind the FFL to check if this buyer purchased another handgun within the prior or following 5 consecutive business days. If so, ATF Form 3310.4 is required.

FORMAT YOUR REPORT:
- Go section by section: Section A (Firearm), Section B (Buyer), Section C (Seller/NICS), Section D (if applicable), Section E (if applicable)
- For each field: note what's recorded and whether it's compliant ✓ or flagged ⚠
- Use bullet points for each question
- End with: OVERALL VERDICT: [APPROVED / REQUIRES CORRECTION / DO NOT TRANSFER]
- If REQUIRES CORRECTION or DO NOT TRANSFER, list all issues in a summary before the verdict line.
- State the verdict ONCE. Do not revise it."""


def get_user_from_token(token):
    r = requests.get(
        f"{SB_URL}/auth/v1/user",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {token}"}
    )
    if r.status_code != 200:
        return None
    return r.json()


def get_profile(user_id):
    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=subscription_status",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    data = r.json()
    return data[0] if data else None


def get_api_key(user_id):
    r = requests.get(
        f"{SB_URL}/rest/v1/api_keys?user_id=eq.{user_id}&select=encrypted_key",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    data = r.json()
    if not data:
        return None
    encrypted = data[0]["encrypted_key"]
    try:
        parts = encrypted.split(":")
        if len(parts) == 3:
            iv = bytes.fromhex(parts[0])
            tag = bytes.fromhex(parts[1])
            ciphertext = bytes.fromhex(parts[2])
            aesgcm = AESGCM(ENCRYPTION_KEY)
            decrypted = aesgcm.decrypt(iv, ciphertext + tag, None)
            return decrypted.decode("utf-8")
        return encrypted
    except Exception:
        return encrypted


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/audit", methods=["POST", "OPTIONS"])
def audit():
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    profile = get_profile(user["id"])
    if not profile or profile.get("subscription_status") != "active":
        return jsonify({"error": "Subscription not active"}), 403

    api_key = get_api_key(user["id"])
    if not api_key:
        return jsonify({"error": "No API key saved. Go to Settings to add your Anthropic API key."}), 400

    body = request.get_json()
    file_name = body.get("fileName", "form.pdf")
    file_data = body.get("fileData", "")
    file_type = body.get("fileType", "application/pdf")

    ext = file_name.rsplit(".", 1)[-1].lower()
    if ext in ["jpg", "jpeg", "png", "webp", "heic"]:
        mime_map = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp", "heic": "image/heic"}
        content_block = {
            "type": "image",
            "source": {"type": "base64", "media_type": mime_map.get(ext, "image/jpeg"), "data": file_data}
        }
    else:
        content_block = {
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": file_data}
        }

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [{
                "role": "user",
                "content": [
                    content_block,
                    {"type": "text", "text": f"Please audit this ATF Form 4473 document: {file_name}. Provide a complete compliance audit report."}
                ]
            }]
        },
        timeout=120
    )

    data = response.json()
    if "error" in data:
        return jsonify({"error": data["error"].get("message", "API error")}), 400

    report = data.get("content", [{}])[0].get("text", "No response from AI.")
    return jsonify({"report": report})


@app.route("/save-api-key", methods=["POST", "OPTIONS"])
def save_api_key():
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    body = request.get_json()
    api_key = body.get("apiKey", "")
    if not api_key.startswith("sk-ant-"):
        return jsonify({"error": "Invalid API key format"}), 400

    # Encrypt
    iv = os.urandom(16)
    aesgcm = AESGCM(ENCRYPTION_KEY)
    encrypted_with_tag = aesgcm.encrypt(iv, api_key.encode(), None)
    tag = encrypted_with_tag[-16:]
    ciphertext = encrypted_with_tag[:-16]
    stored = f"{iv.hex()}:{tag.hex()}:{ciphertext.hex()}"

    r = requests.post(
        f"{SB_URL}/rest/v1/api_keys",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates"
        },
        json={"user_id": user["id"], "encrypted_key": stored}
    )

    if r.status_code not in [200, 201]:
        return jsonify({"error": "Failed to save key"}), 500
    return jsonify({"success": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8247))
    app.run(host="0.0.0.0", port=port)
