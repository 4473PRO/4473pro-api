from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import json
import base64
import hashlib
import hmac
import io
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
CORS(app, origins=["https://4473pro.com", "https://www.4473pro.com"])

from flask import make_response

def _cors_ok():
    r = make_response("", 200)
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return r

import stripe

# --- PDF Instruction Page Stripper ---
try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

_INSTRUCTION_KEYWORDS = [
    "INSTRUCTIONS FOR QUESTION",
    "Instructions to Transferor",
    "Instructions to Transferee",
    "Transferor/Seller Instructions",
    "Transferee/Buyer Instructions",
    "GENERAL INSTRUCTIONS",
    "PURPOSE OF THE FORM",
    "Penalties provided in 18 U.S.C. 924",
    "OMB No. 1140",
    "NOTICE: Prepare in original only",
]

def _is_instruction_page(page_text):
    text_upper = page_text.upper()
    matches = sum(1 for kw in _INSTRUCTION_KEYWORDS if kw.upper() in text_upper)
    return matches >= 2

def strip_instruction_pages(pdf_base64):
    """Remove ATF instruction pages from PDF before sending to AI. Returns original if anything fails."""
    if not PYPDF_AVAILABLE:
        return pdf_base64
    try:
        pdf_bytes = base64.b64decode(pdf_base64)
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        writer = pypdf.PdfWriter()
        kept = 0
        for page in reader.pages:
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            if not _is_instruction_page(text):
                writer.add_page(page)
                kept += 1
        if kept == 0:
            return pdf_base64  # safety: never send empty PDF
        output = io.BytesIO()
        writer.write(output)
        return base64.b64encode(output.getvalue()).decode('utf-8')
    except Exception:
        return pdf_base64  # fail silently, return original


SB_URL = os.environ.get("SUPABASE_URL")
SB_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
ENCRYPTION_KEY = bytes.fromhex(os.environ.get("ENCRYPTION_KEY", "0" * 64))
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")

# 4473 Pro product IDs — subscription products only (ignore other Stripe products)
VALID_PRODUCT_IDS = {"prod_U5zaGkcmpaayRM", "prod_U5zrlcGBf3n0V0"}

# Credit block products are identified by name prefix in the webhook
CREDIT_PRODUCT_PREFIX = "4473 Pro Audit Credits"

# Owner account — always has unlimited audits regardless of credit balance
OWNER_EMAIL = "info@4473pro.com"

SYSTEM_PROMPT = """You are an expert ATF Form 4473 compliance auditor with deep knowledge of federal firearms regulations, ATF instructions, and Gun Control Act requirements. Your job is to carefully examine each Form 4473 and any supporting documents provided, then produce a thorough compliance audit report.

AUDIT SECTIONS:
Examine every field in Sections A, B, C, D, and E of the Form 4473 (August 2023 revision, mandatory since February 2024).

VERDICT DEFINITIONS — USE EXACTLY ONE AT THE END:
- APPROVED: Zero issues found anywhere. Every field complete, accurate, and compliant.
- REQUIRES CORRECTION: Any issue, discrepancy, missing field, or flag was found — even minor ones.
- DO NOT TRANSFER: Buyer is prohibited or a legal disqualifier is present AND the firearm was transferred anyway.

CRITICAL VERDICT RULES:
- NEVER revise your verdict. State it once at the end, correctly the first time.
- If you mention ANY issue, flag, discrepancy, or correction anywhere in your report — the verdict MUST be REQUIRES CORRECTION, not APPROVED.
- APPROVED means absolutely zero flags or issues anywhere in the entire report.
- Only DO NOT TRANSFER for actual legal disqualifiers: prohibited person, underage buyer, or "Yes" answer to Q21.b or Q21.n — AND only if a transfer date appears in Section E confirming the firearm was transferred despite the disqualifier.

DENIED NICS — CRITICAL RULE:
- If NICS was DENIED and NO transfer date is present in Section E → the dealer correctly refused the transfer → verdict is APPROVED (or REQUIRES CORRECTION if other unrelated issues exist). Do NOT issue DO NOT TRANSFER.
- If NICS was DENIED and a transfer date IS present in Section E → the dealer transferred the firearm despite the denial → verdict is DO NOT TRANSFER.
- A correctly handled NICS denial is compliant dealer behavior. Never penalize the compliance score for it.

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

30-DAY NICS EXPIRATION RULE:
- A NICS check is valid for 30 calendar days from the date it was initiated (Section C NICS date).
- If the transfer date in Section E is more than 30 calendar days after the NICS initiation date in Section C → flag as REQUIRES CORRECTION. A new NICS check was required before transfer.
- If both dates are present and the gap is 30 days or fewer → COMPLIANT.
- If only one date is visible and you cannot determine the gap, note it but do not flag unless other evidence supports a violation.

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

MILITARY BUYER RULES (ATF Form 4473 August 2023 Revision, ATF Ruling 2001-5, 18 U.S.C. 921(b)):
- Under the August 2023 revision of Form 4473, Q10 requires only the buyer's actual residential address. Active-duty service members list their off-post residential address in Q10. Do NOT flag Q10 for failing to also list a duty station address — that requirement no longer exists on the current form revision.
- Q26c is where the duty station and PCS orders are documented. If Q26c is populated with the duty station (base name, city, state) and PCS orders are present, the military documentation is complete.
- OUT-OF-STATE HANDGUN — MILITARY EXCEPTION: If the Q10 state differs from the FFL's state for a handgun transfer, do NOT automatically flag as a cross-state residency violation. First check:
  1. Is Q26c populated with a duty station? If yes, this is likely an active-duty military transfer.
  2. Is the buyer's ID consistent with either the duty station state OR the Q10 residence state? If yes → document as a compliant military transfer. Do NOT flag as cross-state residency issue.
  3. If Q10 state differs from FFL state AND Q26c is blank AND no military documentation is present → flag as cross-state residency issue requiring correction.
- FORT CAMPBELL SPECIAL CASE: Fort Campbell is unique — the installation physically straddles the Kentucky/Tennessee state line. Soldiers assigned to Fort Campbell are legal residents of BOTH states and may purchase handguns from FFLs in either KY or TN. If Q26c references Fort Campbell (any variation: "Fort Campbell", "Ft. Campbell", "Ft Campbell", KY 42223 or TN zip codes on-post) → the transfer is compliant regardless of whether the FFL is in KY or TN and regardless of whether the buyer's Q10 address is in KY or TN.
- MILITARY PCS ORDER DATE LOGIC: PCS orders are valid as long as they were issued BEFORE the transfer date. A soldier with PCS orders dated in a prior year (e.g., October 2025) who transfers a firearm in a later year (e.g., March 2026) has valid, current orders — the earlier date means the orders were issued well before the transfer, which is correct and compliant. Do NOT flag PCS orders because their issue date precedes the transfer date. Only flag if PCS orders are dated AFTER the transfer date, which would mean the orders were not yet in effect at the time of transfer.
- Other duty stations near state lines (e.g., Fort Eisenhower/Georgia, Fort Novosel/Alabama) follow the general military exception above but do NOT have Fort Campbell's unique dual-state legal residency status.

OUT-OF-STATE ID RULES:
- For LONG GUN transfers: an out-of-state ID is fully acceptable. Federal law permits long gun transfers to residents of any state. Do NOT flag out-of-state IDs or require supplemental documentation for long gun transfers.
- For HANDGUN transfers: the buyer must be a resident of the FFL's state. If the ID shows a different state than the FFL's state, apply the MILITARY BUYER RULES above before flagging. If no military exception applies, flag as REQUIRES CORRECTION.

SECTION A — FIREARM DESCRIPTION RULES:
- Q1 Manufacturer/Importer: For imported firearms, BOTH the foreign manufacturer AND the U.S. importer must be listed (e.g., "HS Produkt / Springfield Armory"). If only one is recorded for an imported firearm, flag as REQUIRES CORRECTION.
- DOMESTIC MANUFACTURER RULE: Many well-known firearms manufacturers are U.S.-based and NEVER require an importer. Do NOT flag a missing importer for any of the following domestic manufacturers (and any other manufacturer you recognize as U.S.-based): Ruger, Smith & Wesson, S&W, Colt, Remington, Mossberg, Savage, Marlin, Henry, Kimber, Daniel Defense, Windham Weaponry, Anderson Manufacturing, Aero Precision, Del-Ton, DPMS, Bushmaster, Les Baer, Wilson Combat, Ed Brown, Nighthawk Custom, Rock Island Armory (US models), Kahr Arms, Kel-Tec, Hi-Point, Taurus USA, Diamondback, LWRC, BCM (Bravo Company), Stag Arms, Christensen Arms, Weatherby (US-made models), Barrett, Alexander Arms, Franklin Armory, Palmetto State Armory, PSA, FN America, FN America LLC. If the manufacturer is clearly a U.S. company, no importer is required — do not flag.
- FN AMERICA SPECIAL NOTE: FN America LLC manufactures firearms in Columbia, South Carolina including the FN 15 series (AR-15/M16 pattern rifles and lower receivers), M4, and M16 military variants. FN America is a U.S.-based manufacturer — do NOT confuse it with its Belgian parent company FN Herstal. Any firearm marked "FN America", "FN America LLC", or bearing Columbia, SC rollmarks is domestically manufactured and requires NO importer listing.
- Q1 Privately Made Firearm (PMF): If the firearm is a PMF, it must be identified as such in Q1. PMFs must be marked with the FFL's abbreviated license number as a prefix before transfer.
- Q2 Model, Q3 Serial Number, Q4 Type, Q5 Caliber/Gauge: All must be present and complete. A missing or blank serial number is only acceptable for certain pre-1968 firearms (record "NSN" or "None Visible"). Flag any other blank serial number.
- Serial number transcription: If a disposition receipt is present, verify the serial number on the 4473 matches exactly. Transposed digits or character substitutions (0 vs O, 1 vs l) are REQUIRES CORRECTION.

SECTION B — BUYER ELIGIBILITY RULES:
- Q10 Address: Must be a physical residential address, not a P.O. Box. Flag P.O. Box addresses as REQUIRES CORRECTION.
- Q10 "Reside in City Limits": This checkbox is required on the current (August 2023) form revision. If it is blank or unanswered, flag as REQUIRES CORRECTION.
- Q10 State of Residence checkbox: May be answered Yes, No, OR Unknown. "Unknown" is a valid and accepted answer on the form — do NOT flag it as missing or incomplete.
- Q18 Buyer Signature: Must be present. A missing buyer signature is REQUIRES CORRECTION.
- Q19 Buyer Certification Date: Must be present. A missing or blank certification date is REQUIRES CORRECTION.
- Q21.a "Are you the actual transferee/buyer?": Must be answered "Yes." A "No" answer is REQUIRES CORRECTION (possible straw purchase — the FFL must not complete the transfer).
- Q21.b Straw Purchase / Prohibited Person Intent: Must be answered "No." A "Yes" answer means the buyer intends to transfer the firearm to a prohibited person — this is DO NOT TRANSFER, not merely REQUIRES CORRECTION.
- Q21.c through Q21.l Prohibited Person Questions: Any "Yes" answer is DO NOT TRANSFER. Review each carefully.
- Q21.m Nonimmigrant Visa: A "Yes" answer requires follow-up — check whether an exception applies (e.g., hunting license, waiver). If no exception is documented, flag as REQUIRES CORRECTION or DO NOT TRANSFER based on circumstances.
- Q21.n Trafficking / Felony Intent: Must be answered "No." A "Yes" answer is DO NOT TRANSFER.
- All Q21 questions must be answered. Any blank eligibility question is REQUIRES CORRECTION.

SECTION D — RECERTIFICATION RULES:
- Section D is required whenever the actual firearm transfer does NOT occur on the same day the buyer completed and signed Section B.
- Common situations requiring Section D: NICS delay response, state-mandated waiting period, buyer picks up firearm on a different day than they completed the form.
- If the Section B date and the Section E transfer date are different AND Section D is blank or missing → flag as REQUIRES CORRECTION.
- If Section B date and transfer date are the same day → Section D is N/A, do not flag.
- Section D requires the buyer's signature and date on the day of actual transfer, re-certifying that Section B answers are still true and correct.

SECTION E — TRANSFEROR CERTIFICATION RULES:
- Section E must be complete before the firearm is transferred. Every field is required:
  - Transfer date: Must be present. Flag if blank.
  - FFL license number: Must be present. Flag if blank.
  - Trade/corporate name of FFL: Must be present. Flag if blank.
  - Transferor's printed name: Must be present. Flag if blank.
  - Transferor's signature: Must be present. Flag if blank.
- Section E certifies that the transfer occurred within 30 days of the NICS check, that the transferor verified the buyer's ID, and that the transferor has no reason to believe the buyer is prohibited. Incomplete Section E is one of the most frequently cited ATF violations.

DISPOSITION RECEIPT NOTATION RULES:
- NEVER interpret or flag internal FFL notations on disposition receipts. Notes like "Trans", "PSA", "BWO", "SK Trans", transfer codes, source abbreviations, and similar internal recordkeeping notations are for the FFL's internal use only and have no bearing on 4473 compliance.
- Q8 (Private Party Transfer) should only be evaluated based on what is on the 4473 itself, never based on disposition receipt notations.

MULTI-COPY FORM RULES (ATF Ruling 2022-1):
- If two copies of the same 4473 are present in the submission, treat them as follows:
  - FIRST COPY = the original form. Audit it normally. Any missing or incorrect fields on the original are real errors and must be flagged.
  - SECOND COPY = the corrected copy per ATF Ruling 2022-1. Under this ruling, corrections to a 4473 are made on a copy of the original; the corrected copy is electronically attached to and retained with the original as the permanent record.
  - Do NOT treat the first copy as a "preliminary" or "draft" form and give it a pass. The first copy is the original and its errors count.
  - The corrected copy (second copy) should be evaluated for whether the corrections address the original errors. If the corrected copy is complete and compliant, note it as compliant per ATF Ruling 2022-1.
  - The overall verdict should reflect: original had flagged error(s); corrected copy is compliant per ATF Ruling 2022-1 — if the correction resolves the issue, the verdict may be APPROVED if no other open issues remain.

FILE-LEVEL VERDICT RULES (Multiple 4473s in one file):
- A single submitted file may contain multiple Form 4473s due to corrections, NICS delays, overturns, or re-submissions. This is normal and expected.
- YOU MUST AUDIT EVERY FORM IN THE FILE. Do not skip any form, even if an earlier form appears correct.
- After auditing all forms, render a SINGLE file-level verdict based on the OVERALL compliance of the complete file:
  - If the file contains a valid, fully compliant 4473 that properly supersedes or documents any prior forms (corrections, delays, overturns) → the file-level verdict is APPROVED. Do not penalize the file for the existence of earlier corrected or delayed forms — that is the normal ATF-compliant process.
  - Only issue REQUIRES CORRECTION if there is an unresolved compliance problem that is NOT addressed by any other form or supporting document in the file.
  - A file with an original error AND a proper correction on file is a COMPLIANT file, not a REQUIRES CORRECTION file.

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

SSN ADVISORY:
- Q12 Social Security Number is optional and its absence is NOT an error. Do not flag a blank SSN.
- If SSN is blank and the form received a NICS Delay response, include an advisory note (not a flag) that providing the SSN can help resolve delayed responses more quickly.

TENNESSEE TICS "G" DESIGNATOR RULE:
- In Tennessee, the TICS (Tennessee Instant Check System) uses a "G" prefix on transaction numbers (e.g., 26G013952) to designate a stolen gun check — a firearm-only check, NOT a buyer background check.
- A "G" receipt is generated when a firearm is added to a 4473 after the background check has already been initiated or returned. The FFL runs a separate stolen gun check on the added firearm; TICS assigns it a "G" transaction number.
- The "G" receipt is purely supplemental documentation kept with the form. It is NEVER recorded in Q27.b. Q27.b contains only the buyer background check transaction number (e.g., a "W" series number like 26W091642).
- NEVER compare a "G" receipt number against Q27.b. They are completely different transactions. A mismatch between a "G" number and a "W" number is NOT a discrepancy — it is expected and correct.
- When a "G" receipt is present in submitted documents, note it as expected supplemental documentation for an added firearm. Do not flag it as a discrepancy or require investigation.

3310.4 MULTIPLE HANDGUN ALERT:
- If a handgun or pistol is being transferred, note the transfer date and remind the FFL to check if this buyer purchased another handgun within the prior or following 5 consecutive business days. If so, ATF Form 3310.4 is required.

FORMAT YOUR REPORT:
- Go section by section: Section A (Firearm), Section B (Buyer), Section C (Seller/NICS), Section D (Recertification), Section E (Transferor Certification)
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
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=subscription_status,state,business_name,onboarding_completed,ccw_exempt,owner_pin,delayed_transfer_rule,q32_notation_patterns,pawn_shop_mode,sot_dealer,custom_rules,email,audit_credits,audit_credits_used,access_until,created_by_admin",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    data = r.json()
    return data[0] if data else None


# get_api_key removed — API key is now managed server-side via OWNER_ANTHROPIC_KEY


def set_subscription_status(email, status, stripe_customer_id=None, stripe_subscription_id=None):
    """Find user by email and update their subscription status."""
    # Look up user in Supabase auth
    r = requests.get(
        f"{SB_URL}/auth/v1/admin/users",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    if r.status_code != 200:
        return False
    users = r.json().get("users", [])
    user = next((u for u in users if u.get("email", "").lower() == email.lower()), None)
    if not user:
        return False

    update_data = {"subscription_status": status}
    if stripe_customer_id:
        update_data["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id:
        update_data["stripe_subscription_id"] = stripe_subscription_id

    r2 = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json=update_data
    )
    return r2.status_code in [200, 204]


def create_supabase_user(email, stripe_customer_id, stripe_subscription_id):
    """Create a new Supabase user and mark them active."""
    import secrets, string
    temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))

    r = requests.post(
        f"{SB_URL}/auth/v1/admin/users",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "email": email,
            "password": temp_password,
            "email_confirm": True
        }
    )
    if r.status_code not in [200, 201]:
        return False

    user_id = r.json().get("id")
    if not user_id:
        return False

    # Upsert profile
    requests.post(
        f"{SB_URL}/rest/v1/profiles",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates"
        },
        json={
            "id": user_id,
            "email": email,
            "subscription_status": "active",
            "stripe_customer_id": stripe_customer_id,
            "stripe_subscription_id": stripe_subscription_id
        }
    )

    # Send password reset email so user can set their own password
    requests.post(
        f"{SB_URL}/auth/v1/admin/users/{user_id}/recover",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json={"redirect_to": "https://4473pro.com/set-password.html"}
    )
    return True


@app.route("/claim-account", methods=["POST", "OPTIONS"])
def claim_account():
    """Called from success.html after Stripe checkout. Returns a session token so the user
    can set their password immediately without needing an email link."""
    if request.method == "OPTIONS":
        return "", 200

    body = request.get_json()
    session_id = body.get("session_id", "")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    try:
        stripe.api_key = STRIPE_SECRET_KEY
        session = stripe.checkout.Session.retrieve(session_id)
        email = session.get("customer_details", {}).get("email", "") or session.get("customer_email", "")
        if not email:
            return jsonify({"error": "Could not determine email from session"}), 400

        # Verify this is a 4473 Pro purchase
        line_items = stripe.checkout.Session.list_line_items(session_id)
        is_valid = False
        for item in line_items.data:
            price_id = getattr(getattr(item, 'price', None), 'id', None)
            if price_id:
                price = stripe.Price.retrieve(price_id, expand=["product"])
                product_id = price.product.id if hasattr(price.product, 'id') else price.product
                if product_id in VALID_PRODUCT_IDS:
                    is_valid = True
                    break
        if not is_valid:
            return jsonify({"error": "Not a valid 4473 Pro purchase"}), 403

        # Look up user in Supabase
        r = requests.get(
            f"{SB_URL}/auth/v1/admin/users",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
        )
        users = r.json().get("users", [])
        user = next((u for u in users if u.get("email", "").lower() == email.lower()), None)
        if not user:
            return jsonify({"error": "Account not ready yet. Please wait a moment and try again."}), 404

        # Generate a magic link / sign-in link for the user
        r2 = requests.post(
            f"{SB_URL}/auth/v1/admin/users/{user['id']}/magic-link",
            headers={
                "apikey": SB_SERVICE_KEY,
                "Authorization": f"Bearer {SB_SERVICE_KEY}",
                "Content-Type": "application/json"
            },
            json={"email": email}
        )

        # Use the OTP endpoint instead to get a token directly
        r3 = requests.post(
            f"{SB_URL}/auth/v1/admin/generate_link",
            headers={
                "apikey": SB_SERVICE_KEY,
                "Authorization": f"Bearer {SB_SERVICE_KEY}",
                "Content-Type": "application/json"
            },
            json={"type": "magiclink", "email": email}
        )

        if r3.status_code in [200, 201]:
            link_data = r3.json()
            # Extract the token from the generated link
            action_link = link_data.get("action_link", "")
            # Parse token from link
            import urllib.parse
            parsed = urllib.parse.urlparse(action_link)
            fragment = urllib.parse.parse_qs(parsed.fragment)
            access_token = fragment.get("access_token", [None])[0]
            refresh_token = fragment.get("refresh_token", [None])[0]
            if access_token:
                return jsonify({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "email": email
                })

        return jsonify({"error": "Could not generate login token. Please use the forgot password link."}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def is_4473_product(session_or_invoice):
    """Check if a Stripe session/invoice is for a 4473 Pro product."""
    try:
        stripe.api_key = STRIPE_SECRET_KEY
        # For checkout sessions, check line items
        if "line_items" in str(type(session_or_invoice)):
            items = stripe.checkout.Session.list_line_items(session_or_invoice.id)
        else:
            items = session_or_invoice.get("lines", {}).get("data", [])
        for item in (items.data if hasattr(items, 'data') else items):
            price_id = item.get("price", {}).get("id") or getattr(getattr(item, 'price', None), 'id', None)
            if price_id:
                price = stripe.Price.retrieve(price_id, expand=["product"])
                product_id = getattr(price.product, 'id', None) or price.product
                if product_id in VALID_PRODUCT_IDS:
                    return True
    except Exception:
        pass
    return False


def _add_credits_for_email(email, amount):
    """Add audit credits to a user account by email. Credits accumulate — never expire."""
    try:
        r = requests.get(
            f"{SB_URL}/rest/v1/profiles?email=eq.{email}&select=id,audit_credits",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
        )
        profiles = r.json()
        if not profiles:
            return
        profile = profiles[0]
        current = profile.get("audit_credits") or 0
        requests.patch(
            f"{SB_URL}/rest/v1/profiles?id=eq.{profile['id']}",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}", "Content-Type": "application/json"},
            json={"audit_credits": current + amount}
        )
    except Exception:
        pass


@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        email = data.get("customer_details", {}).get("email", "")
        customer_id = data.get("customer", "")
        subscription_id = data.get("subscription", "")
        if not email:
            return jsonify({"status": "no email"}), 200

        stripe.api_key = STRIPE_SECRET_KEY
        try:
            items = stripe.checkout.Session.list_line_items(data["id"])
            is_subscription = False
            credits_to_add = 0

            for item in items.data:
                price = stripe.Price.retrieve(item.price.id, expand=["product"])
                product_id = price.product.id if hasattr(price.product, 'id') else price.product
                product_name = price.product.name if hasattr(price.product, 'name') else ""

                if product_id in VALID_PRODUCT_IDS:
                    is_subscription = True

                elif product_name.startswith(CREDIT_PRODUCT_PREFIX):
                    # Parse credit count from product name e.g. "4473 Pro Audit Credits — 25"
                    try:
                        parts = product_name.split("—")
                        credits_to_add += int(parts[-1].strip())
                    except Exception:
                        pass

            if is_subscription:
                # New subscription purchase — create/activate account and add 10 credits
                updated = set_subscription_status(email, "active", customer_id, subscription_id)
                if not updated:
                    create_supabase_user(email, customer_id, subscription_id)
                # Add 10 credits for new subscription
                _add_credits_for_email(email, 10)

            elif credits_to_add > 0:
                # Credit block purchase — add credits to existing account
                _add_credits_for_email(email, credits_to_add)

        except Exception as e:
            pass

    elif event_type == "invoice.paid":
        email = data.get("customer_email", "")
        customer_id = data.get("customer", "")
        subscription_id = data.get("subscription", "")
        if not email:
            return jsonify({"status": "no email"}), 200
        # Check product — only handle subscription renewals here
        is_4473 = False
        for line in data.get("lines", {}).get("data", []):
            price_id = line.get("price", {}).get("id")
            if price_id:
                try:
                    stripe.api_key = STRIPE_SECRET_KEY
                    price = stripe.Price.retrieve(price_id, expand=["product"])
                    product_id = price.product.id if hasattr(price.product, 'id') else price.product
                    if product_id in VALID_PRODUCT_IDS:
                        is_4473 = True
                        break
                except Exception:
                    pass
        if not is_4473:
            return jsonify({"status": "not a 4473 Pro product"}), 200
        set_subscription_status(email, "active", customer_id, subscription_id)
        # Add 10 credits on every subscription renewal
        _add_credits_for_email(email, 10)

    elif event_type == "customer.subscription.deleted":
        customer_id = data.get("customer", "")
        # Find user by stripe_customer_id and deactivate
        if customer_id:
            r = requests.get(
                f"{SB_URL}/rest/v1/profiles?stripe_customer_id=eq.{customer_id}&select=id",
                headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
            )
            profiles = r.json()
            if profiles:
                user_id = profiles[0]["id"]
                requests.patch(
                    f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}",
                    headers={
                        "apikey": SB_SERVICE_KEY,
                        "Authorization": f"Bearer {SB_SERVICE_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={"subscription_status": "cancelled"}
                )

    return jsonify({"status": "ok"}), 200



def health():
    return jsonify({"status": "ok"})


def get_system_status():
    """Fetch current maintenance mode from system_settings."""
    try:
        r = requests.get(
            f"{SB_URL}/rest/v1/system_settings?id=eq.1&select=maintenance_mode,maintenance_message,maintenance_window",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
        )
        data = r.json()
        return data[0] if data else {"maintenance_mode": "off", "maintenance_message": "", "maintenance_window": ""}
    except Exception:
        return {"maintenance_mode": "off", "maintenance_message": "", "maintenance_window": ""}


@app.route("/system-status", methods=["GET", "OPTIONS"])
def system_status():
    """Public endpoint — app polls this for maintenance banner."""
    if request.method == "OPTIONS":
        return "", 200
    return jsonify(get_system_status())


def build_system_prompt(ccw_exempt=False, ccw_permit_name=None, business_name=None,
                        delayed_transfer_rule=None,
                        q32_notation_patterns=None, pawn_shop_mode=False,
                        sot_dealer=False, custom_rules=None):
    prompt = SYSTEM_PROMPT

    # Delayed transfer rule
    delay_rule = (delayed_transfer_rule or 'default_proceed').strip()
    if delay_rule == 'approval_required':
        prompt += (
            "\n\nDELAYED TRANSFER RULE — STATE-SPECIFIC: In this FFL's state, a 'Delayed' "
            "NICS response does NOT generate a 'can transfer by' date. The FFL must "
            "wait for an explicit APPROVAL before transferring. Do NOT flag the absence of "
            "a 'can transfer by' date on delayed transfers — it is not required here. "
            "Only flag if the form shows a transfer was completed while status was still "
            "'Delayed' without a documented approval."
        )

    # Q32 notation patterns
    if q32_notation_patterns and q32_notation_patterns.strip():
        patterns = q32_notation_patterns.strip()
        prompt += (
            f"\n\nQ32 NOTATION RULES — FFL-SPECIFIC: This FFL uses the following standard "
            f"notations in Question 32. Do NOT flag these as errors or anomalies — they are "
            f"documented internal procedures: {patterns}."
        )

    # Pawn shop mode
    if pawn_shop_mode:
        prompt += (
            "\n\nPAWN SHOP MODE: This FFL is a pawn shop. Pawn redemptions require a new "
            "Form 4473 and background check even though the customer previously owned the "
            "firearm. Treat pawn redemptions the same as retail sales for 4473 compliance."
        )

    # SOT/Class III dealer
    if sot_dealer:
        prompt += (
            "\n\nSOT/CLASS III DEALER: This FFL holds a Special Occupational Taxpayer "
            "designation and transfers NFA items. For NFA transfers: Question 28 exemption "
            "applies. ATF Form 4 or Form 3 approval documentation supersedes standard "
            "background check requirements where applicable."
        )

    # CCW NICS exemption
    if ccw_exempt:
        prompt += (
            "\n\nSTATE-SPECIFIC RULE — CCW NICS EXEMPTION: This FFL's state allows "
            "firearm transfers without a NICS background check when the buyer presents "
            "a valid concealed carry permit (any state-issued CCW/carry permit). "
            "If any concealed carry permit, handgun carry permit, or equivalent is "
            "documented anywhere on the form (including Section D or buyer notes), "
            "treat Section C NICS fields as N/A — do not flag them as missing or incomplete. "
            "The permit must appear to have been issued within the last 5 years to qualify. "
            "Accept any common abbreviation (HCP, CCDW, CWP, CFP, LTC, CPL, etc.)."
        )

    # Custom FFL rules (appended last)
    if custom_rules and custom_rules.strip():
        prompt += (
            f"\n\nFFL-SPECIFIC CUSTOM RULES: The following rules have been configured by "
            f"this FFL based on their specific operational procedures. Apply these rules "
            f"during your audit. These supplement but do not override federal compliance "
            f"requirements:\n{custom_rules.strip()}"
        )

    # Business name
    if business_name:
        prompt += f"\n\nFFL BUSINESS: This audit is being run for {business_name}."

    return prompt


@app.route("/save-profile", methods=["POST", "OPTIONS"])
def save_profile():
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    body = request.get_json()
    pin = body.get("owner_pin", "").strip()
    update_data = {
        "onboarding_completed": True,
        "business_name": body.get("business_name", ""),
        "ffl_number": body.get("ffl_number", ""),
        "phone": body.get("phone", ""),
        "state": body.get("state", ""),
        "monthly_transfers": body.get("monthly_transfers", ""),
        "ccw_exempt": body.get("ccw_exempt", False),
    }
    if pin and len(pin) == 4 and pin.isdigit():
        update_data["owner_pin"] = pin

    r = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json=update_data
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to save profile"}), 500
    return jsonify({"success": True})


@app.route("/get-profile", methods=["GET", "OPTIONS"])
def get_profile_route():
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    profile = get_profile(user["id"])
    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    return jsonify(profile)


@app.route("/audit", methods=["POST", "OPTIONS"])
def audit():
    if request.method == "OPTIONS":
        return "", 200

    # Block new audits if maintenance is active
    status = get_system_status()
    if status.get("maintenance_mode") == "active":
        msg = status.get("maintenance_message") or "System maintenance in progress."
        window = status.get("maintenance_window", "")
        detail = f" Estimated completion: {window}." if window else " Please check back shortly."
        return jsonify({"error": f"Audits paused — {msg}{detail} No credits have been charged."}), 503

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    profile = get_profile(user["id"])
    if not profile or profile.get("subscription_status") != "active":
        return jsonify({"error": "Subscription not active"}), 403

    # Check access_until for admin-created (time-limited) accounts
    import datetime as _dt
    _access_until = profile.get("access_until")
    if _access_until and profile.get("created_by_admin"):
        try:
            _expiry = _dt.datetime.fromisoformat(_access_until.replace("Z", "+00:00")).replace(tzinfo=None)
            if _dt.datetime.utcnow() > _expiry:
                return jsonify({"error": "Trial access has expired. Please subscribe to continue."}), 403
        except Exception:
            pass

    # Check and deduct audit credits (owner account is exempt)
    user_email = profile.get("email", "") or user.get("email", "")
    is_owner = (user_email.lower() == OWNER_EMAIL.lower())
    if not is_owner:
        credits = profile.get("audit_credits", 0) or 0
        if credits <= 0:
            return jsonify({"error": "No audit credits remaining. Purchase more credits from your billing page."}), 403
        # Deduct 1 credit atomically
        requests.patch(
            f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}", "Content-Type": "application/json"},
            json={
                "audit_credits": credits - 1,
                "audit_credits_used": (profile.get("audit_credits_used") or 0) + 1
            }
        )

    api_key = OWNER_ANTHROPIC_KEY
    if not api_key:
        return jsonify({"error": "Server configuration error. Please contact support."}), 500

    body = request.get_json()
    file_name = body.get("fileName", "form.pdf")
    file_data = body.get("fileData", "")
    file_type = body.get("fileType", "application/pdf")

    # Strip ATF instruction pages before sending to AI (reduces token cost)
    file_data = strip_instruction_pages(file_data)

    content_block = {
        "type": "document",
        "source": {"type": "base64", "media_type": "application/pdf", "data": file_data}
    }

    ccw_exempt = profile.get("ccw_exempt", False)
    business_name = profile.get("business_name", "")
    system_prompt = build_system_prompt(
        ccw_exempt=ccw_exempt,
        business_name=business_name,
        delayed_transfer_rule=profile.get("delayed_transfer_rule", "default_proceed"),
        q32_notation_patterns=profile.get("q32_notation_patterns", ""),
        pawn_shop_mode=profile.get("pawn_shop_mode", False),
        sot_dealer=profile.get("sot_dealer", False),
        custom_rules=profile.get("custom_rules", "")
    )

    # Inject destination-state restrictions if buyer state provided
    buyer_state = body.get("buyerState", "").strip().upper()
    if buyer_state and len(buyer_state) == 2:
        try:
            sr = requests.get(
                f"{SB_URL}/rest/v1/state_transfer_restrictions?state_code=eq.{buyer_state}&active=eq.true",
                headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"},
                timeout=5
            )
            restrictions = sr.json()
            if restrictions:
                state_name = restrictions[0].get("state_name", buyer_state)
                block_items = [r for r in restrictions if r["restriction_level"] == "block"]
                verify_items = [r for r in restrictions if r["restriction_level"] == "verify"]
                note_items = [r for r in restrictions if r["restriction_level"] == "note"]
                state_section = f"\n\nDESTINATION-STATE RESTRICTIONS — BUYER IS A {state_name.upper()} RESIDENT:"
                if block_items:
                    state_section += "\nThe following restrictions BLOCK or prevent this transfer unless documented exceptions are present:"
                    for r in block_items:
                        state_section += f"\n• [{r['firearm_type'].upper()}] {r['description']}"
                if verify_items:
                    state_section += "\nThe following items REQUIRE VERIFICATION before transfer:"
                    for r in verify_items:
                        state_section += f"\n• [{r['firearm_type'].upper()}] {r['description']}"
                if note_items:
                    state_section += "\nAdditional notes for this buyer's state:"
                    for r in note_items:
                        state_section += f"\n• [{r['firearm_type'].upper()}] {r['description']}"
                state_section += f"\nLast verified: {restrictions[0].get('last_verified', 'unknown')}. Flag any missing documentation required by these state laws."
                system_prompt += state_section
        except Exception:
            pass  # Fail silently — don't block the audit if state lookup fails

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "prompt-caching-2024-07-31"
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 8192,
            "system": [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"}
                }
            ],
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


# /save-api-key endpoint removed — API key is now managed server-side


@app.route("/admin/usage-this-month", methods=["GET", "OPTIONS"])
def admin_usage_this_month():
    """Return total forms audited per user since a given date."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    since = request.args.get("since", "")
    query = f"{SB_URL}/rest/v1/audit_history?select=profile_id,total_forms"
    if since:
        query += f"&created_at=gte.{since}"

    r = requests.get(
        query,
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    rows = r.json() if r.status_code == 200 else []

    # Aggregate total_forms per profile_id
    counts = {}
    for row in rows:
        pid = row.get("profile_id")
        if pid:
            counts[pid] = counts.get(pid, 0) + (row.get("total_forms") or 0)

    result = [{"profile_id": pid, "total_forms": total} for pid, total in counts.items()]
    return jsonify(result)


@app.route("/save-audit-history", methods=["POST", "OPTIONS"])
def save_audit_history():
    """Save a completed audit batch to Supabase for history review."""
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    body = request.get_json()
    results = body.get("results", [])
    if not results:
        return jsonify({"error": "No results to save"}), 400

    approved = sum(1 for r in results if r.get("verdict") == "approved")
    correction = sum(1 for r in results if r.get("verdict") == "correction")
    block = sum(1 for r in results if r.get("verdict") == "block")
    error = sum(1 for r in results if r.get("verdict") == "error")

    r = requests.post(
        f"{SB_URL}/rest/v1/audit_history",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        },
        json={
            "profile_id": user["id"],
            "total_forms": len(results),
            "approved_count": approved,
            "correction_count": correction,
            "block_count": block,
            "error_count": error,
            "results": results
        }
    )

    if r.status_code not in [200, 201]:
        return jsonify({"error": "Failed to save audit history"}), 500
    return jsonify({"success": True, "id": r.json()[0].get("id") if r.json() else None})


@app.route("/cancel-subscription", methods=["POST", "OPTIONS"])
def cancel_subscription():
    """Cancel the user's Stripe subscription at period end."""
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    # Get stripe subscription ID from profile
    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}&select=stripe_subscription_id",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    profiles = r.json()
    if not profiles or not profiles[0].get("stripe_subscription_id"):
        return jsonify({"error": "No active subscription found"}), 404

    sub_id = profiles[0]["stripe_subscription_id"]

    try:
        stripe.api_key = STRIPE_SECRET_KEY
        # Cancel at period end — they keep access until the billing period runs out
        stripe.Subscription.modify(sub_id, cancel_at_period_end=True)
        return jsonify({"success": True, "message": "Your subscription has been cancelled. You will retain full access until the end of your current billing period."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
OWNER_ANTHROPIC_KEY = os.environ.get("OWNER_ANTHROPIC_KEY", "")

# Cache freshness threshold — entries older than this trigger a background refresh
CACHE_MAX_AGE_DAYS = 7

# All state + firearm type combinations for the nightly refresh
ALL_STATES = [
    "Alabama","Alaska","Arizona","Arkansas","California","Colorado","Connecticut",
    "Delaware","Florida","Georgia","Hawaii","Idaho","Illinois","Indiana","Iowa",
    "Kansas","Kentucky","Louisiana","Maine","Maryland","Massachusetts","Michigan",
    "Minnesota","Mississippi","Missouri","Montana","Nebraska","Nevada","New Hampshire",
    "New Jersey","New Mexico","New York","North Carolina","North Dakota","Ohio",
    "Oklahoma","Oregon","Pennsylvania","Rhode Island","South Carolina","South Dakota",
    "Tennessee","Texas","Utah","Vermont","Virginia","Washington","West Virginia",
    "Wisconsin","Wyoming"
]

STATE_NAME_TO_CODE = {
    "Alabama":"AL","Alaska":"AK","Arizona":"AZ","Arkansas":"AR","California":"CA",
    "Colorado":"CO","Connecticut":"CT","Delaware":"DE","Florida":"FL","Georgia":"GA",
    "Hawaii":"HI","Idaho":"ID","Illinois":"IL","Indiana":"IN","Iowa":"IA",
    "Kansas":"KS","Kentucky":"KY","Louisiana":"LA","Maine":"ME","Maryland":"MD",
    "Massachusetts":"MA","Michigan":"MI","Minnesota":"MN","Mississippi":"MS",
    "Missouri":"MO","Montana":"MT","Nebraska":"NE","Nevada":"NV","New Hampshire":"NH",
    "New Jersey":"NJ","New Mexico":"NM","New York":"NY","North Carolina":"NC",
    "North Dakota":"ND","Ohio":"OH","Oklahoma":"OK","Oregon":"OR","Pennsylvania":"PA",
    "Rhode Island":"RI","South Carolina":"SC","South Dakota":"SD","Tennessee":"TN",
    "Texas":"TX","Utah":"UT","Vermont":"VT","Virginia":"VA","Washington":"WA",
    "West Virginia":"WV","Wisconsin":"WI","Wyoming":"WY"
}

FIREARM_TYPES_FOR_CACHE = ["long_gun"]

def verify_admin(request):
    """Check admin secret from header."""
    return request.headers.get("X-Admin-Secret", "") == ADMIN_SECRET and ADMIN_SECRET != ""

def log_rule_change(user_id, field_name, old_value, new_value, changed_by="user"):
    """Write a rule change to the audit log."""
    requests.post(
        f"{SB_URL}/rest/v1/rule_change_log",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "user_id": user_id,
            "field_name": field_name,
            "old_value": str(old_value) if old_value is not None else "",
            "new_value": str(new_value) if new_value is not None else "",
            "changed_by": changed_by
        }
    )


@app.route("/save-compliance-profile", methods=["POST", "OPTIONS"])
def save_compliance_profile():
    """Save compliance profile fields. Logs any rule changes."""
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

    body = request.get_json()

    # Fields that are tracked for rule change logging
    tracked_fields = [
        "delayed_transfer_rule", "q32_notation_patterns",
        "pawn_shop_mode", "sot_dealer", "ccw_exempt", "ccw_permit_name", "custom_rules"
    ]

    update_data = {}
    for field in tracked_fields:
        if field in body:
            new_val = body[field]
            old_val = profile.get(field)
            update_data[field] = new_val
            # Log if value actually changed
            if str(old_val) != str(new_val):
                log_rule_change(user["id"], field, old_val, new_val, changed_by="user")

    if not update_data:
        return jsonify({"success": True, "message": "No changes"})

    r = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json=update_data
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to save compliance profile"}), 500
    return jsonify({"success": True})


@app.route("/get-rule-change-log", methods=["GET", "OPTIONS"])
def get_rule_change_log():
    """Return rule change history for the authenticated user."""
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    r = requests.get(
        f"{SB_URL}/rest/v1/rule_change_log?user_id=eq.{user['id']}&order=changed_at.desc&limit=50",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    return jsonify(r.json())


# ── ADMIN ENDPOINTS ───────────────────────────────────────────

@app.route("/admin/accounts", methods=["GET", "OPTIONS"])
def admin_accounts():
    """List all accounts with profile data."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?select=id,email,subscription_status,business_name,state,ffl_number,stripe_customer_id,stripe_subscription_id,created_by_admin,cancelled_at,created_at,delayed_transfer_rule,q32_notation_patterns,pawn_shop_mode,sot_dealer,ccw_exempt,ccw_permit_name,custom_rules,admin_notes,access_until&order=created_at.desc",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    return jsonify(r.json())


@app.route("/admin/account/<user_id>", methods=["GET", "OPTIONS"])
def admin_get_account(user_id):
    """Get a single account with full details."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    # Profile
    pr = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=*",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    # Rule change log
    lr = requests.get(
        f"{SB_URL}/rest/v1/rule_change_log?user_id=eq.{user_id}&order=changed_at.desc",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    profiles = pr.json()
    profile = profiles[0] if profiles else {}
    return jsonify({"profile": profile, "rule_changes": lr.json()})


@app.route("/admin/create-account", methods=["POST", "OPTIONS"])
def admin_create_account():
    """Admin manually creates and activates an account."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json()
    email = body.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    admin_notes = body.get("admin_notes", "Admin-created account")
    access_days = int(body.get("access_days", 30))
    success = create_supabase_user(email, None, None)
    if not success:
        return jsonify({"error": "Failed to create account — email may already exist"}), 400

    # Set admin_notes, created_by_admin, and access_until
    import datetime
    access_until = (datetime.datetime.utcnow() + datetime.timedelta(days=access_days)).isoformat()
    ru = requests.get(
        f"{SB_URL}/auth/v1/admin/users",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    users = ru.json().get("users", [])
    user = next((u for u in users if u.get("email", "").lower() == email), None)
    if user:
        requests.patch(
            f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
            headers={
                "apikey": SB_SERVICE_KEY,
                "Authorization": f"Bearer {SB_SERVICE_KEY}",
                "Content-Type": "application/json"
            },
            json={"created_by_admin": True, "admin_notes": admin_notes, "access_until": access_until}
        )

    return jsonify({"success": True, "email": email, "access_until": access_until})


@app.route("/admin/update-account/<user_id>", methods=["POST", "OPTIONS"])
def admin_update_account(user_id):
    """Admin updates account fields (subscription status, admin notes, compliance profile)."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json()
    allowed = [
        "subscription_status", "admin_notes", "delayed_transfer_rule", "access_until", "access_until",
        "q32_notation_patterns", "pawn_shop_mode", "sot_dealer", "ccw_exempt",
        "ccw_permit_name", "custom_rules", "business_name", "ffl_number", "phone", "state"
    ]

    # Handle email change separately via Supabase Admin API
    new_email = body.get("email", "").strip()
    new_password = body.get("password", "").strip()

    # Get current profile for change logging
    pr = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=*",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    profiles = pr.json()
    current = profiles[0] if profiles else {}

    update_data = {k: v for k, v in body.items() if k in allowed}

    errors = []

    # Update email via Supabase Admin API
    if new_email:
        er = requests.put(
            f"{SB_URL}/auth/v1/admin/users/{user_id}",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}", "Content-Type": "application/json"},
            json={"email": new_email}
        )
        if er.status_code not in [200, 204]:
            errors.append(f"Email update failed: {er.text}")

    # Update password via Supabase Admin API
    if new_password:
        pr2 = requests.put(
            f"{SB_URL}/auth/v1/admin/users/{user_id}",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}", "Content-Type": "application/json"},
            json={"password": new_password}
        )
        if pr2.status_code not in [200, 204]:
            errors.append(f"Password update failed: {pr2.text}")

    # Log rule changes made by admin
    rule_fields = ["delayed_transfer_rule", "q32_notation_patterns",
                   "pawn_shop_mode", "sot_dealer", "ccw_exempt", "ccw_permit_name", "custom_rules"]
    for field in rule_fields:
        if field in update_data and str(current.get(field)) != str(update_data[field]):
            log_rule_change(user_id, field, current.get(field), update_data[field], changed_by="admin")

    if update_data:
        r = requests.patch(
            f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}",
            headers={
                "apikey": SB_SERVICE_KEY,
                "Authorization": f"Bearer {SB_SERVICE_KEY}",
                "Content-Type": "application/json"
            },
            json=update_data
        )
        if r.status_code not in [200, 204]:
            errors.append("Profile update failed")

    if errors:
        return jsonify({"success": False, "errors": errors}), 500
    return jsonify({"success": True})


@app.route("/state-restrictions", methods=["GET", "OPTIONS"])
def get_state_restrictions():
    """Public endpoint — returns all active state restrictions."""
    if request.method == "OPTIONS":
        return "", 200
    r = requests.get(
        f"{SB_URL}/rest/v1/state_transfer_restrictions?active=eq.true&order=state_code.asc",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    return jsonify(r.json())


@app.route("/state-restrictions/<state_code>", methods=["GET", "OPTIONS"])
def get_state_restrictions_by_state(state_code):
    """Get restrictions for a specific state."""
    if request.method == "OPTIONS":
        return "", 200
    r = requests.get(
        f"{SB_URL}/rest/v1/state_transfer_restrictions?state_code=eq.{state_code.upper()}&active=eq.true&order=firearm_type.asc",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    return jsonify(r.json())


@app.route("/admin/state-restrictions", methods=["GET", "POST", "OPTIONS"])
def admin_state_restrictions():
    """Admin — list all or add a restriction."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        r = requests.get(
            f"{SB_URL}/rest/v1/state_transfer_restrictions?order=state_code.asc,firearm_type.asc",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
        )
        return jsonify(r.json())

    # POST — add new restriction
    body = request.get_json()
    required = ["state_code", "state_name", "firearm_type", "restriction_type", "restriction_level", "description"]
    for f in required:
        if not body.get(f):
            return jsonify({"error": f"Missing required field: {f}"}), 400
    body["updated_at"] = "now()"
    body["verified_by"] = "admin"
    r = requests.post(
        f"{SB_URL}/rest/v1/state_transfer_restrictions",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        },
        json=body
    )
    if r.status_code not in [200, 201]:
        return jsonify({"error": "Failed to add restriction"}), 500
    return jsonify(r.json())


@app.route("/admin/state-restrictions/<restriction_id>", methods=["POST", "DELETE", "OPTIONS"])
def admin_state_restriction(restriction_id):
    """Admin — update or deactivate a restriction."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "DELETE":
        r = requests.patch(
            f"{SB_URL}/rest/v1/state_transfer_restrictions?id=eq.{restriction_id}",
            headers={
                "apikey": SB_SERVICE_KEY,
                "Authorization": f"Bearer {SB_SERVICE_KEY}",
                "Content-Type": "application/json"
            },
            json={"active": False, "updated_at": "now()"}
        )
        return jsonify({"success": r.status_code in [200, 204]})

    body = request.get_json()
    body["updated_at"] = "now()"
    body["verified_by"] = "admin"
    r = requests.patch(
        f"{SB_URL}/rest/v1/state_transfer_restrictions?id=eq.{restriction_id}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json=body
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Update failed"}), 500
    return jsonify({"success": True})


TRANSFER_CHECK_PROMPT = """You are a firearm transfer compliance specialist with expertise in state firearm laws across all 50 US states.

A Federal Firearms Licensee (FFL) is asking whether they can transfer a firearm to a buyer who is a resident of a specific state.

IMPORTANT RULES:
- Federal law generally requires an FFL to conduct the transfer through a dealer in the BUYER'S home state for handguns
- For long guns, federal law permits direct transfer if legal in BOTH the FFL's state AND the buyer's state
- Many states have ADDITIONAL requirements beyond federal law (waiting periods, permits, registrations, etc.)
- Your job is to identify these state-specific restrictions clearly and accurately

You MUST search the web for current information about the buyer's state firearm laws before answering. Laws change frequently.

Respond ONLY with a valid JSON object — no preamble, no markdown, no explanation outside the JSON. Use this exact structure:
{
  "verdict": "CLEAR" | "RESTRICTED" | "BLOCKED" | "VERIFY",
  "summary": "Plain English summary of the situation — include all relevant details, do not truncate",
  "restrictions": [
    {
      "type": "permit" | "wait" | "block" | "other",
      "label": "Short restriction name",
      "description": "Detailed explanation of this specific restriction"
    }
  ],
  "ffl_action": "What the FFL should specifically do in this situation",
  "sources": ["Source citation 1", "Source citation 2"]
}

Verdict definitions:
- CLEAR: No restrictions beyond standard federal requirements
- RESTRICTED: Transfer may be possible but additional steps required (permits, waiting periods, etc.)
- BLOCKED: Transfer cannot be completed by an out-of-state FFL under current law
- VERIFY: Situation is complex or laws are in flux — FFL must verify before proceeding

Be accurate and current. If a law has recently changed, note that."""


def run_transfer_check_ai(buyer_state, firearm_type, ffl_state="the FFL's state"):
    """
    Core AI lookup — calls Anthropic with web_search using the owner key.
    Returns parsed result dict or raises Exception.
    """
    if not OWNER_ANTHROPIC_KEY:
        raise Exception("Owner API key not configured on server.")

    user_query = (
        f"I am an FFL dealer. A buyer whose state of residence is {buyer_state} "
        f"wants to purchase a {firearm_type} from my store. "
        f"What are the current state-specific restrictions or requirements I need to be aware of for this transfer? "
        f"Please search for the most current {buyer_state} firearm transfer laws as of today."
    )

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": OWNER_ANTHROPIC_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 4096,
            "system": TRANSFER_CHECK_PROMPT,
            "tools": [{"type": "web_search_20250305", "name": "web_search"}],
            "messages": [{"role": "user", "content": user_query}]
        },
        timeout=90
    )

    if response.status_code != 200:
        raise Exception(f"AI API returned {response.status_code}: {response.text[:200]}")

    data = response.json()
    result_text = ""
    for block in data.get("content", []):
        if block.get("type") == "text":
            result_text += block.get("text", "")

    if not result_text:
        raise Exception("No text response from AI.")

    clean = result_text.strip()
    if clean.startswith("```"):
        clean = clean.split("```")[1]
        if clean.startswith("json"):
            clean = clean[4:]
    clean = clean.strip()

    try:
        return json.loads(clean)
    except Exception:
        return {
            "verdict": "VERIFY",
            "summary": result_text[:500],
            "restrictions": [],
            "ffl_action": "Review the information above and consult with a compliance attorney.",
            "sources": []
        }


def get_cache_entry(state_code, firearm_type):
    """Fetch a single cache entry from Supabase. Returns entry dict or None."""
    try:
        r = requests.get(
            f"{SB_URL}/rest/v1/transfer_check_cache"
            f"?state_code=eq.{state_code}&firearm_type=eq.{firearm_type}&select=*",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"},
            timeout=5
        )
        data = r.json()
        return data[0] if data else None
    except Exception:
        return None


def upsert_cache_entry(state_code, firearm_type, result):
    """Write or update a cache entry in Supabase."""
    payload = {
        "state_code": state_code,
        "firearm_type": firearm_type,
        "verdict": result.get("verdict", "VERIFY"),
        "summary": result.get("summary", ""),
        "restrictions": result.get("restrictions", []),
        "ffl_action": result.get("ffl_action", ""),
        "sources": result.get("sources", []),
        "cached_at": "now()"
    }
    requests.post(
        f"{SB_URL}/rest/v1/transfer_check_cache",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates"
        },
        json=payload,
        timeout=10
    )


def is_cache_fresh(entry):
    """Return True if cached_at is within CACHE_MAX_AGE_DAYS."""
    if not entry or not entry.get("cached_at"):
        return False
    from datetime import datetime, timezone, timedelta
    try:
        cached_str = entry["cached_at"]
        # Supabase returns ISO format with timezone
        cached_at = datetime.fromisoformat(cached_str.replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - cached_at
        return age < timedelta(days=CACHE_MAX_AGE_DAYS)
    except Exception:
        return False


@app.route("/transfer-check", methods=["POST", "OPTIONS"])
def transfer_check():
    """
    State transfer restriction lookup.
    Returns cached result instantly if fresh (< 7 days).
    Falls back to live AI lookup if cache is stale or missing.
    No longer uses the user's Anthropic API key.
    """
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

    # Check access_until for admin-created (time-limited) accounts
    import datetime as _dt
    _access_until = profile.get("access_until")
    if _access_until and profile.get("created_by_admin"):
        try:
            _expiry = _dt.datetime.fromisoformat(_access_until.replace("Z", "+00:00")).replace(tzinfo=None)
            if _dt.datetime.utcnow() > _expiry:
                return jsonify({"error": "Trial access has expired. Please subscribe to continue."}), 403
        except Exception:
            pass

    body = request.get_json()
    buyer_state = body.get("buyer_state", "").strip()
    firearm_type = body.get("firearm_type", "").strip()
    force_refresh = body.get("force_refresh", False)

    if not buyer_state or not firearm_type:
        return jsonify({"error": "buyer_state and firearm_type are required"}), 400

    # Map full state name to 2-letter code for cache lookup
    state_code = STATE_NAME_TO_CODE.get(buyer_state, buyer_state[:2].upper())

    # ── Cache-first lookup ──────────────────────────────────────
    if not force_refresh:
        entry = get_cache_entry(state_code, firearm_type)
        if entry and is_cache_fresh(entry):
            result = {
                "verdict": entry["verdict"],
                "summary": entry["summary"],
                "restrictions": entry["restrictions"] if isinstance(entry["restrictions"], list) else [],
                "ffl_action": entry["ffl_action"],
                "sources": entry["sources"] if isinstance(entry["sources"], list) else [],
                "cached_at": entry["cached_at"],
                "from_cache": True
            }
            return jsonify(result)

    # ── Live AI lookup (cache miss, stale, or forced refresh) ──
    try:
        ffl_state = profile.get("state", "the FFL's state")
        result = run_transfer_check_ai(buyer_state, firearm_type, ffl_state)
        # Store result in cache for next time
        upsert_cache_entry(state_code, firearm_type, result)
        result["cached_at"] = None
        result["from_cache"] = False
        return jsonify(result)
    except Exception as e:
        # If live lookup fails but we have a stale cache entry, return it with a warning
        stale_entry = get_cache_entry(state_code, firearm_type)
        if stale_entry:
            result = {
                "verdict": stale_entry["verdict"],
                "summary": stale_entry["summary"],
                "restrictions": stale_entry["restrictions"] if isinstance(stale_entry["restrictions"], list) else [],
                "ffl_action": stale_entry["ffl_action"],
                "sources": stale_entry["sources"] if isinstance(stale_entry["sources"], list) else [],
                "cached_at": stale_entry["cached_at"],
                "from_cache": True,
                "stale_warning": "Live refresh failed. Showing cached data — verify currency before relying on this result."
            }
            return jsonify(result)
        return jsonify({"error": f"Lookup failed: {str(e)}"}), 500


@app.route("/admin/cache-status", methods=["GET", "OPTIONS"])
def admin_cache_status():
    """Return cache coverage stats for the admin panel."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        r = requests.get(
            f"{SB_URL}/rest/v1/transfer_check_cache?select=state_code,firearm_type,verdict,cached_at&order=cached_at.desc",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"},
            timeout=10
        )
        entries = r.json()
        total_expected = len(ALL_STATES) * len(FIREARM_TYPES_FOR_CACHE)
        fresh = sum(1 for e in entries if is_cache_fresh(e))
        stale = len(entries) - fresh
        missing = total_expected - len(entries)
        oldest = min((e["cached_at"] for e in entries if e.get("cached_at")), default=None)
        newest = max((e["cached_at"] for e in entries if e.get("cached_at")), default=None)
        return jsonify({
            "total_entries": len(entries),
            "total_expected": total_expected,
            "fresh": fresh,
            "stale": stale,
            "missing": missing,
            "oldest_entry": oldest,
            "newest_entry": newest,
            "entries": entries
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/refresh-cache", methods=["POST", "OPTIONS"])
def admin_refresh_cache():
    """
    Trigger a cache refresh for all 50 states × long_gun.
    Full refresh runs in a background thread and returns immediately.
    Single-entry refresh (state_code + firearm_type) runs synchronously.
    Protected by admin secret. Triggered manually from back office.
    """
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    if not OWNER_ANTHROPIC_KEY:
        return jsonify({"error": "OWNER_ANTHROPIC_KEY not set on server. Add it to Render environment variables."}), 500

    import time
    import threading

    body = request.get_json(silent=True) or {}
    specific_state = body.get("state_code", "").strip().upper()
    specific_type = body.get("firearm_type", "").strip()

    # Single entry refresh — run synchronously (fast, ~30 sec)
    if specific_state and specific_type:
        state_name = next((n for n, c in STATE_NAME_TO_CODE.items() if c == specific_state), specific_state)
        try:
            result = run_transfer_check_ai(state_name, specific_type)
            upsert_cache_entry(specific_state, specific_type, result)
            return jsonify({"message": f"Refreshed {specific_state}/{specific_type} successfully.", "results": {"success": 1, "failed": 0, "errors": []}})
        except Exception as e:
            return jsonify({"message": "Refresh failed.", "results": {"success": 0, "failed": 1, "errors": [str(e)]}}), 500

    # Full refresh — run in background thread, respond immediately
    def run_full_refresh():
        work = [
            (code, name, ft)
            for name, code in STATE_NAME_TO_CODE.items()
            for ft in FIREARM_TYPES_FOR_CACHE
        ]
        for i, (state_code, state_name, firearm_type) in enumerate(work):
            try:
                result = run_transfer_check_ai(state_name, firearm_type)
                upsert_cache_entry(state_code, firearm_type, result)
            except Exception:
                pass  # Individual failures are silent — retry manually if needed
            if i < len(work) - 1:
                time.sleep(3)

    thread = threading.Thread(target=run_full_refresh, daemon=True)
    thread.start()

    return jsonify({
        "message": "Full cache refresh started in background. All 50 entries will be updated over the next 3–5 minutes. Click 'Reload Stats' to check progress.",
        "results": {"success": 0, "failed": 0, "errors": []}
    })


@app.route("/admin/clear-cache", methods=["POST", "OPTIONS"])
def admin_clear_cache():
    """
    Delete all entries from transfer_check_cache.
    Protected by admin secret. Used to force fresh lookups after a fix.
    """
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        r = requests.delete(
            f"{SB_URL}/rest/v1/transfer_check_cache?state_code=neq.IMPOSSIBLE_PLACEHOLDER",
            headers={
                "apikey": SB_SERVICE_KEY,
                "Authorization": f"Bearer {SB_SERVICE_KEY}",
                "Prefer": "return=minimal"
            },
            timeout=10
        )
        if r.status_code in (200, 204):
            return jsonify({"message": "Cache cleared successfully. All future lookups will run fresh."})
        else:
            return jsonify({"error": f"Supabase returned {r.status_code}: {r.text[:200]}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/admin/extend-access/<user_id>", methods=["POST", "OPTIONS"])
def admin_extend_access(user_id):
    """
    Extend access for an admin-created account by N days from today (or from
    current access_until if not yet expired, whichever is later).
    For Stripe subscribers, delays next billing via trial_end.
    """
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    import datetime
    body = request.get_json(silent=True) or {}
    days = int(body.get("days", 30))
    if days not in (30, 60, 90):
        return jsonify({"error": "Invalid days value. Must be 30, 60, or 90."}), 400

    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=email,subscription_status,stripe_subscription_id,access_until,created_by_admin",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"},
        timeout=10
    )
    profiles = r.json()
    if not profiles:
        return jsonify({"error": "User not found"}), 404
    profile = profiles[0]

    stripe_sub_id = profile.get("stripe_subscription_id", "")

    if stripe_sub_id:
        try:
            import stripe as stripe_lib
            stripe_lib.api_key = STRIPE_SECRET_KEY
            sub = stripe_lib.Subscription.retrieve(stripe_sub_id)
            current_end = sub.get("current_period_end", 0)
            new_anchor = current_end + (days * 86400)
            stripe_lib.Subscription.modify(
                stripe_sub_id,
                trial_end=new_anchor,
                proration_behavior="none"
            )
            return jsonify({
                "success": True,
                "message": f"Billing extended by {days} days. Next charge pushed to {datetime.datetime.utcfromtimestamp(new_anchor).strftime('%b %d, %Y')}."
            })
        except Exception as e:
            return jsonify({"error": f"Stripe error: {str(e)}"}), 500
    else:
        current_until = profile.get("access_until")
        if current_until:
            try:
                base = datetime.datetime.fromisoformat(current_until.replace("Z", "+00:00")).replace(tzinfo=None)
                base = max(base, datetime.datetime.utcnow())
            except Exception:
                base = datetime.datetime.utcnow()
        else:
            base = datetime.datetime.utcnow()

        new_until = (base + datetime.timedelta(days=days)).isoformat()
        requests.patch(
            f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}",
            headers={
                "apikey": SB_SERVICE_KEY,
                "Authorization": f"Bearer {SB_SERVICE_KEY}",
                "Content-Type": "application/json"
            },
            json={"access_until": new_until, "subscription_status": "active"},
            timeout=10
        )
        return jsonify({
            "success": True,
            "message": f"Access extended by {days} days. Active until {datetime.datetime.fromisoformat(new_until).strftime('%b %d, %Y')}."
        })


@app.route("/admin/cancel-subscription/<user_id>", methods=["POST", "OPTIONS"])
def admin_cancel_subscription(user_id):
    """Admin: immediately cancel a user's Stripe subscription and mark account cancelled."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    # Get profile
    pr = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=stripe_subscription_id,email,subscription_status",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    profiles = pr.json()
    if not profiles or not profiles[0]:
        return jsonify({"error": "User not found"}), 404

    profile = profiles[0]
    sub_id = profile.get("stripe_subscription_id")

    body = request.get_json(silent=True) or {}
    immediate = body.get("immediate", True)  # default: cancel immediately

    # Cancel in Stripe if subscription exists
    stripe_result = None
    if sub_id:
        try:
            stripe.api_key = STRIPE_SECRET_KEY
            if immediate:
                stripe.Subscription.cancel(sub_id)
            else:
                stripe.Subscription.modify(sub_id, cancel_at_period_end=True)
            stripe_result = "cancelled" if immediate else "cancel_at_period_end"
        except Exception as e:
            # If sub not found in Stripe, still update Supabase
            stripe_result = f"stripe_error: {str(e)}"

    # Update Supabase profile
    import datetime
    update = {
        "subscription_status": "cancelled",
        "cancelled_at": datetime.datetime.utcnow().isoformat()
    }
    r = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json=update
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to update Supabase profile"}), 500

    return jsonify({
        "success": True,
        "user_id": user_id,
        "email": profile.get("email"),
        "stripe_result": stripe_result,
        "immediate": immediate
    })


@app.route("/admin/reactivate-subscription/<user_id>", methods=["POST", "OPTIONS"])
def admin_reactivate_subscription(user_id):
    """Admin: reactivate a cancelled account (Supabase only — no Stripe sub restoration)."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    pr = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=email,subscription_status",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    profiles = pr.json()
    if not profiles or not profiles[0]:
        return jsonify({"error": "User not found"}), 404

    r = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json={"subscription_status": "active", "cancelled_at": None}
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to update profile"}), 500

    return jsonify({"success": True, "email": profiles[0].get("email")})


@app.route("/admin/maintenance", methods=["GET", "POST", "OPTIONS"])
def admin_maintenance():
    """Get or set maintenance mode."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        return jsonify(get_system_status())

    body = request.get_json()
    mode = body.get("maintenance_mode", "off")
    if mode not in ("off", "scheduled", "active"):
        return jsonify({"error": "Invalid mode. Use: off, scheduled, active"}), 400

    update = {
        "maintenance_mode": mode,
        "maintenance_message": body.get("maintenance_message", ""),
        "maintenance_window": body.get("maintenance_window", ""),
        "updated_at": "now()"
    }
    r = requests.patch(
        f"{SB_URL}/rest/v1/system_settings?id=eq.1",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json=update
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to update maintenance mode"}), 500
    return jsonify({"success": True, "mode": mode})


@app.route("/update-compliance-field", methods=["POST", "OPTIONS"])
def update_compliance_field():
    """Update a single compliance field — used from settings page after PIN gate verified."""
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    body = request.get_json()
    allowed = {"ccw_exempt"}
    update = {k: v for k, v in body.items() if k in allowed}
    if not update:
        return jsonify({"error": "No valid fields provided"}), 400

    r = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json=update
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to update setting"}), 500
    return jsonify({"success": True})


@app.route("/verify-pin", methods=["POST", "OPTIONS"])
def verify_pin():
    """Verify owner PIN before allowing protected setting changes."""
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    body = request.get_json()
    submitted_pin = str(body.get("pin", "")).strip()

    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}&select=owner_pin",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}"
        }
    )
    if r.status_code not in [200, 206]:
        return jsonify({"error": "Could not verify PIN"}), 500

    rows = r.json()
    if not rows:
        return jsonify({"error": "Profile not found"}), 404

    stored_pin = str(rows[0].get("owner_pin", "") or "").strip()

    if not stored_pin:
        return jsonify({"error": "No PIN set on this account. Please set a PIN in Settings first."}), 400

    if submitted_pin != stored_pin:
        return jsonify({"error": "Incorrect PIN."}), 403

    return jsonify({"success": True})


@app.route("/toggle-ccw-exempt", methods=["POST", "OPTIONS"])
def toggle_ccw_exempt():
    """Toggle CCW NICS exemption — requires PIN verified on client before calling."""
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    body = request.get_json()
    submitted_pin = str(body.get("pin", "")).strip()
    new_value = bool(body.get("ccw_exempt", False))

    # Re-verify PIN server-side on every toggle
    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}&select=owner_pin",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}"
        }
    )
    if r.status_code not in [200, 206]:
        return jsonify({"error": "Could not verify PIN"}), 500

    rows = r.json()
    stored_pin = str(rows[0].get("owner_pin", "") or "").strip() if rows else ""

    if not stored_pin or submitted_pin != stored_pin:
        return jsonify({"error": "Invalid PIN."}), 403

    patch = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json={"ccw_exempt": new_value}
    )
    if patch.status_code not in [200, 204]:
        return jsonify({"error": "Failed to update setting"}), 500

    return jsonify({"success": True, "ccw_exempt": new_value})


@app.route("/set-owner-pin", methods=["POST", "OPTIONS"])
def set_owner_pin():
    """Set or change the owner PIN."""
    if request.method == "OPTIONS":
        return "", 200

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    body = request.get_json()
    new_pin = str(body.get("pin", "")).strip()
    current_pin = str(body.get("current_pin", "")).strip()

    if not new_pin or len(new_pin) != 4 or not new_pin.isdigit():
        return jsonify({"error": "PIN must be exactly 4 digits."}), 400

    # If a PIN already exists, require the current PIN to change it
    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}&select=owner_pin",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}"
        }
    )
    rows = r.json() if r.status_code in [200, 206] else []
    stored_pin = str(rows[0].get("owner_pin", "") or "").strip() if rows else ""

    if stored_pin and current_pin != stored_pin:
        return jsonify({"error": "Current PIN is incorrect."}), 403

    patch = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        },
        json={"owner_pin": new_pin}
    )
    if patch.status_code not in [200, 204]:
        return jsonify({"error": "Failed to save PIN"}), 500

    return jsonify({"success": True})


@app.route("/admin/refresh-state-laws", methods=["POST", "OPTIONS"])
def refresh_state_laws():
    """
    Thursday cron job — refreshes long gun state transfer restrictions via AI web search.
    Called by Supabase pg_cron at 09:00 UTC (03:00 CST) every Friday.
    Updates description, restriction_level, last_verified, updated_at on all
    long_gun and both firearm_type records. Never deletes records.
    """
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    import datetime

    # Fetch all long gun relevant records
    r = requests.get(
        f"{SB_URL}/rest/v1/state_transfer_restrictions"
        f"?firearm_type=in.(long_gun,both)&order=state_code.asc",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    if r.status_code not in [200, 206]:
        return jsonify({"error": "Failed to fetch state restrictions"}), 500

    records = r.json()
    if not records:
        return jsonify({"error": "No records found"}), 404

    today = datetime.date.today().isoformat()
    updated = []
    errors = []

    for rec in records:
        state_code = rec.get("state_code", "")
        state_name = rec.get("state_name", state_code)
        firearm_type = rec.get("firearm_type", "long_gun")
        rec_id = rec.get("id")

        try:
            # Ask AI to research current long gun transfer laws for this state
            research_prompt = (
                f"You are a federal firearms compliance expert. Research the CURRENT {state_name} ({state_code}) "
                f"state laws that affect OUT-OF-STATE long gun (rifle and shotgun) transfers FROM a licensed FFL dealer "
                f"in another state TO a {state_name} resident. Search the web for the most current information. "
                f"Focus only on: waiting periods, permits required, registration requirements, "
                f"prohibited features or models, age requirements beyond federal law, and any outright blocks. "
                "Respond in this exact JSON format with no other text: "
                '{"restriction_level": "block or verify or note or none", '
                '"restriction_type": "short description of restriction type or none", '
                '"description": "1-3 sentence plain English summary for an FFL dealer. Be specific. If no restrictions beyond federal law, say so clearly."}'
            )

            ai_response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 512,
                    "tools": [{"type": "web_search_20250305", "name": "web_search"}],
                    "messages": [{"role": "user", "content": research_prompt}]
                },
                timeout=45
            )

            if ai_response.status_code != 200:
                errors.append(f"{state_code}: AI call failed ({ai_response.status_code})")
                continue

            ai_data = ai_response.json()
            # Extract text from response content blocks
            raw_text = ""
            for block in ai_data.get("content", []):
                if block.get("type") == "text":
                    raw_text += block.get("text", "")

            # Parse JSON from response
            import json as json_lib
            import re
            json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if not json_match:
                errors.append(f"{state_code}: Could not parse AI response")
                continue

            parsed = json_lib.loads(json_match.group())
            restriction_level = parsed.get("restriction_level", rec.get("restriction_level", "note"))
            restriction_type = parsed.get("restriction_type", rec.get("restriction_type", ""))
            description = parsed.get("description", rec.get("description", ""))

            # Validate restriction_level
            if restriction_level not in ("block", "verify", "note", "none"):
                restriction_level = "note"

            # Update the record
            patch = requests.patch(
                f"{SB_URL}/rest/v1/state_transfer_restrictions?id=eq.{rec_id}",
                headers={
                    "apikey": SB_SERVICE_KEY,
                    "Authorization": f"Bearer {SB_SERVICE_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "restriction_level": restriction_level,
                    "restriction_type": restriction_type,
                    "description": description,
                    "last_verified": today,
                    "updated_at": "now()",
                    "verified_by": "ai_cron"
                }
            )

            if patch.status_code in [200, 204]:
                updated.append(state_code)
            else:
                errors.append(f"{state_code}: Patch failed ({patch.status_code})")

        except Exception as e:
            errors.append(f"{state_code}: {str(e)}")
            continue

    return jsonify({
        "success": True,
        "updated": updated,
        "update_count": len(updated),
        "errors": errors,
        "run_date": today
    })


@app.route("/admin/audit-history/<user_id>", methods=["GET", "OPTIONS"])
def admin_get_audit_history(user_id):
    """Get audit history metadata for a user — no report content returned."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    r = requests.get(
        f"{SB_URL}/rest/v1/audit_history"
        f"?select=id,batch_date,total_forms,approved_count,correction_count,block_count,created_at"
        f"&profile_id=eq.{user_id}&order=created_at.desc",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}"
        }
    )
    if r.status_code not in [200, 206]:
        return jsonify({"error": "Failed to fetch audit history"}), 500
    return jsonify(r.json())


@app.route("/admin/audit-history/<user_id>", methods=["DELETE"])
def admin_delete_audit_history(user_id):
    """Permanently delete all audit history for a user."""
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    r = requests.delete(
        f"{SB_URL}/rest/v1/audit_history?profile_id=eq.{user_id}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json"
        }
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to delete audit history", "detail": r.text}), 500
    return jsonify({"success": True})


# ============================================================
# SUB-USER (STAFF) ENDPOINTS
# ============================================================

SB_HEADERS = lambda: {
    "apikey": SB_SERVICE_KEY,
    "Authorization": f"Bearer {SB_SERVICE_KEY}",
    "Content-Type": "application/json"
}

def get_owner_id(user_id):
    """Return owner_id for a user — themselves if owner, parent if staff."""
    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=role,parent_user_id",
        headers=SB_HEADERS()
    )
    if r.status_code != 200 or not r.json():
        return None
    p = r.json()[0]
    if p["role"] == "owner":
        return user_id
    return p.get("parent_user_id")

def require_owner(token):
    """Returns (user, error_response). Ensures caller is an owner."""
    user = get_user_from_token(token)
    if not user:
        return None, (jsonify({"error": "Unauthorized"}), 401)
    profile = get_profile(user["id"])
    if not profile or profile.get("role", "owner") != "owner":
        return None, (jsonify({"error": "Owner account required"}), 403)
    return user, None

@app.route("/create-subuser", methods=["POST", "OPTIONS"])
def create_subuser():
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()
    can_audit = bool(data.get("can_run_audit", False))

    if not username:
        return jsonify({"error": "Username required"}), 400
    if not password or len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    # Check sub-user count (max 6)
    count_r = requests.get(
        f"{SB_URL}/rest/v1/profiles?parent_user_id=eq.{owner['id']}&select=id",
        headers=SB_HEADERS()
    )
    if count_r.status_code == 200 and len(count_r.json()) >= 6:
        return jsonify({"error": "Maximum of 6 staff accounts reached"}), 400

    # Check username not already taken under this owner
    ucheck = requests.get(
        f"{SB_URL}/rest/v1/profiles?username=eq.{username}&parent_user_id=eq.{owner['id']}&select=id",
        headers=SB_HEADERS()
    )
    if ucheck.status_code == 200 and ucheck.json():
        return jsonify({"error": "Username already taken"}), 400

    # Check subscription active
    profile = get_profile(owner["id"])
    if not profile or profile.get("subscription_status") not in ["active", "trialing"]:
        return jsonify({"error": "Active subscription required"}), 403

    # Generate fake internal email
    fake_email = f"{username}@{owner['id']}.internal"

    # Create Supabase auth user with password set by owner
    create_r = requests.post(
        f"{SB_URL}/auth/v1/admin/users",
        headers=SB_HEADERS(),
        json={"email": fake_email, "email_confirm": True, "password": password}
    )
    if create_r.status_code not in [200, 201]:
        body = create_r.json()
        return jsonify({"error": body.get("message", "Failed to create user")}), 400

    new_user = create_r.json()
    new_id = new_user["id"]

    # Upsert profile as staff with username
    requests.post(
        f"{SB_URL}/rest/v1/profiles",
        headers={**SB_HEADERS(), "Prefer": "resolution=merge-duplicates"},
        json={
            "id": new_id,
            "role": "staff",
            "parent_user_id": owner["id"],
            "can_run_audit": can_audit,
            "subscription_status": "active",
            "onboarding_completed": True,
            "username": username
        }
    )

    return jsonify({"success": True, "user_id": new_id})


@app.route("/list-subusers", methods=["GET", "OPTIONS"])
def list_subusers():
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?parent_user_id=eq.{owner['id']}&select=id,role,can_run_audit,username",
        headers=SB_HEADERS()
    )
    if r.status_code != 200:
        return jsonify({"error": "Failed to list staff"}), 500

    staff = r.json()
    result = []
    for s in staff:
        result.append({
            "id": s["id"],
            "username": s.get("username") or "(no username)",
            "can_run_audit": s.get("can_run_audit", False),
            "active": True
        })

    return jsonify({"staff": result})


@app.route("/update-subuser", methods=["POST", "OPTIONS"])
def update_subuser():
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    staff_id = data.get("staff_id")
    can_audit = data.get("can_run_audit")

    if not staff_id:
        return jsonify({"error": "staff_id required"}), 400

    # Verify staff belongs to this owner
    check = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{staff_id}&parent_user_id=eq.{owner['id']}&select=id",
        headers=SB_HEADERS()
    )
    if check.status_code != 200 or not check.json():
        return jsonify({"error": "Staff account not found"}), 404

    patch = {}
    if can_audit is not None:
        patch["can_run_audit"] = bool(can_audit)

    requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{staff_id}",
        headers=SB_HEADERS(),
        json=patch
    )
    return jsonify({"success": True})


@app.route("/delete-subuser", methods=["POST", "OPTIONS"])
def delete_subuser():
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    staff_id = data.get("staff_id")
    if not staff_id:
        return jsonify({"error": "staff_id required"}), 400

    # Verify ownership
    check = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{staff_id}&parent_user_id=eq.{owner['id']}&select=id",
        headers=SB_HEADERS()
    )
    if check.status_code != 200 or not check.json():
        return jsonify({"error": "Staff account not found"}), 404

    # Delete auth user (cascades to profile)
    requests.delete(
        f"{SB_URL}/auth/v1/admin/users/{staff_id}",
        headers=SB_HEADERS()
    )
    return jsonify({"success": True})


@app.route("/lookup-staff-email", methods=["POST", "OPTIONS"])
def lookup_staff_email():
    """Given a username, return the fake internal email for Supabase auth."""
    if request.method == "OPTIONS":
        return _cors_ok()
    data = request.get_json()
    username = (data.get("username") or "").strip().lower()
    if not username:
        return jsonify({"error": "Username required"}), 400

    # Find profile with this username
    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?username=eq.{username}&select=id,parent_user_id,role",
        headers=SB_HEADERS()
    )
    if r.status_code != 200 or not r.json():
        return jsonify({"error": "Username not found"}), 404

    profile = r.json()[0]
    if profile.get("role") != "staff":
        return jsonify({"error": "Username not found"}), 404

    owner_id = profile.get("parent_user_id")
    if not owner_id:
        return jsonify({"error": "Account configuration error"}), 500

    fake_email = f"{username}@{owner_id}.internal"
    return jsonify({"email": fake_email})



@app.route("/get-my-role", methods=["GET", "OPTIONS"])
def get_my_role():
    """Returns the caller's role and owner_id. Used by frontend for routing."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user['id']}&select=role,parent_user_id,can_run_audit",
        headers=SB_HEADERS()
    )
    if r.status_code != 200 or not r.json():
        return jsonify({"role": "owner", "can_run_audit": True})

    p = r.json()[0]
    return jsonify({
        "role": p.get("role", "owner"),
        "parent_user_id": p.get("parent_user_id"),
        "can_run_audit": p.get("can_run_audit", True) if p.get("role") == "owner" else p.get("can_run_audit", False)
    })


# ============================================================
# LEADERBOARD / GRADE DATA ENDPOINT
# ============================================================

@app.route("/get-leaderboard-data", methods=["GET", "OPTIONS"])
def get_leaderboard_data():
    """Return audit history for the owner account — accessible by owner and staff alike.
    Uses service key to bypass RLS so staff tokens can read owner's audit history."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    owner_id = get_owner_id(user["id"])
    if not owner_id:
        return jsonify({"error": "Account error"}), 400

    days = request.args.get("days", "90")
    try:
        days = int(days)
    except Exception:
        days = 90

    try:
        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        r = requests.get(
            f"{SB_URL}/rest/v1/audit_history?profile_id=eq.{owner_id}"
            f"&select=results,batch_date,total_forms,approved_count,correction_count,block_count"
            f"&created_at=gte.{since}&order=created_at.desc",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
        )
        if r.status_code != 200:
            return jsonify({"error": "Supabase error", "status": r.status_code, "detail": r.text}), 500

        rows = r.json()
        return jsonify({"rows": rows, "owner_id": owner_id, "count": len(rows) if isinstance(rows, list) else 0})
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ============================================================
# DAILY TASKS ENDPOINTS
# ============================================================

def get_task_date():
    """Return today's task date — resets at 6am UTC."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    # If before 6am UTC, use yesterday's date as "today"
    if now.hour < 6:
        return (now - timedelta(days=1)).date().isoformat()
    return now.date().isoformat()


@app.route("/get-daily-tasks", methods=["GET", "OPTIONS"])
def get_daily_tasks():
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    owner_id = get_owner_id(user["id"])
    if not owner_id:
        return jsonify({"error": "Account error"}), 400

    task_date = get_task_date()

    # Get all active tasks for this account
    tasks_r = requests.get(
        f"{SB_URL}/rest/v1/daily_tasks?owner_id=eq.{owner_id}&active=eq.true&order=sort_order.asc",
        headers=SB_HEADERS()
    )
    tasks = tasks_r.json() if tasks_r.status_code == 200 else []

    # Get today's completions
    comp_r = requests.get(
        f"{SB_URL}/rest/v1/daily_task_completions?owner_id=eq.{owner_id}&task_date=eq.{task_date}&select=task_id,initials,completed_at",
        headers=SB_HEADERS()
    )
    completions = comp_r.json() if comp_r.status_code == 200 else []
    comp_map = {c["task_id"]: c for c in completions}

    result = []
    for t in tasks:
        c = comp_map.get(t["id"])
        result.append({
            "id": t["id"],
            "title": t["title"],
            "sort_order": t["sort_order"],
            "completed": c is not None,
            "initials": c["initials"] if c else None,
            "completed_at": c["completed_at"] if c else None
        })

    return jsonify({"tasks": result, "task_date": task_date})


@app.route("/complete-task", methods=["POST", "OPTIONS"])
def complete_task():
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    task_id = data.get("task_id")
    initials = (data.get("initials") or "").strip().upper()[:4]

    if not task_id or not initials:
        return jsonify({"error": "task_id and initials required"}), 400

    owner_id = get_owner_id(user["id"])
    task_date = get_task_date()

    # Verify task belongs to this account
    check = requests.get(
        f"{SB_URL}/rest/v1/daily_tasks?id=eq.{task_id}&owner_id=eq.{owner_id}&select=id",
        headers=SB_HEADERS()
    )
    if check.status_code != 200 or not check.json():
        return jsonify({"error": "Task not found"}), 404

    # Upsert completion (one completion per task per day)
    requests.post(
        f"{SB_URL}/rest/v1/daily_task_completions",
        headers={**SB_HEADERS(), "Prefer": "resolution=merge-duplicates"},
        json={
            "task_id": task_id,
            "owner_id": owner_id,
            "initials": initials,
            "task_date": task_date,
            "completed_at": "now()"
        }
    )
    return jsonify({"success": True})


@app.route("/uncomplete-task", methods=["POST", "OPTIONS"])
def uncomplete_task():
    """Allow undoing a task completion (same-day only)."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    task_id = data.get("task_id")
    owner_id = get_owner_id(user["id"])
    task_date = get_task_date()

    requests.delete(
        f"{SB_URL}/rest/v1/daily_task_completions?task_id=eq.{task_id}&owner_id=eq.{owner_id}&task_date=eq.{task_date}",
        headers=SB_HEADERS()
    )
    return jsonify({"success": True})


@app.route("/task-log", methods=["GET", "OPTIONS"])
def task_log():
    """7-day completion log for owner review."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).date().isoformat()

    # Join completions with task titles
    r = requests.get(
        f"{SB_URL}/rest/v1/daily_task_completions?owner_id=eq.{owner['id']}&task_date=gte.{cutoff}&select=task_id,initials,task_date,completed_at,daily_tasks(title)&order=task_date.desc,completed_at.desc",
        headers=SB_HEADERS()
    )
    rows = r.json() if r.status_code == 200 else []
    result = []
    for row in rows:
        result.append({
            "task_title": row.get("daily_tasks", {}).get("title", "Unknown"),
            "initials": row["initials"],
            "task_date": row["task_date"],
            "completed_at": row["completed_at"]
        })

    return jsonify({"log": result})


@app.route("/save-task", methods=["POST", "OPTIONS"])
def save_task():
    """Create or update a daily task (owner only)."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    task_id = data.get("id")
    title = (data.get("title") or "").strip()
    sort_order = int(data.get("sort_order", 0))

    if not title:
        return jsonify({"error": "Title required"}), 400

    if task_id:
        # Update existing
        requests.patch(
            f"{SB_URL}/rest/v1/daily_tasks?id=eq.{task_id}&owner_id=eq.{owner['id']}",
            headers=SB_HEADERS(),
            json={"title": title, "sort_order": sort_order}
        )
    else:
        # Create new
        r = requests.post(
            f"{SB_URL}/rest/v1/daily_tasks",
            headers={**SB_HEADERS(), "Prefer": "return=representation"},
            json={"owner_id": owner["id"], "title": title, "sort_order": sort_order}
        )
        if r.status_code not in [200, 201]:
            return jsonify({"error": "Failed to save task"}), 500
        task_id = r.json()[0]["id"] if r.json() else None

    return jsonify({"success": True, "id": task_id})


@app.route("/delete-task", methods=["POST", "OPTIONS"])
def delete_task():
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    task_id = data.get("task_id")
    if not task_id:
        return jsonify({"error": "task_id required"}), 400

    requests.delete(
        f"{SB_URL}/rest/v1/daily_tasks?id=eq.{task_id}&owner_id=eq.{owner['id']}",
        headers=SB_HEADERS()
    )
    return jsonify({"success": True})


@app.route("/reorder-tasks", methods=["POST", "OPTIONS"])
def reorder_tasks():
    """Update sort_order for multiple tasks at once."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    tasks = data.get("tasks", [])  # [{id, sort_order}, ...]

    for t in tasks:
        requests.patch(
            f"{SB_URL}/rest/v1/daily_tasks?id=eq.{t['id']}&owner_id=eq.{owner['id']}",
            headers=SB_HEADERS(),
            json={"sort_order": t["sort_order"]}
        )

    return jsonify({"success": True})


# ============================================================
# KNOWLEDGE BASE / POLICY LIBRARY ENDPOINTS
# ============================================================

@app.route("/kb/search", methods=["GET", "OPTIONS"])
def kb_search():
    """Search knowledge base — returns owner's entries + global entries."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    owner_id = get_owner_id(user["id"])
    query = request.args.get("q", "").strip()

    if not query:
        # Return all entries for this account + global, ordered by title
        r = requests.get(
            f"{SB_URL}/rest/v1/knowledge_base?or=(owner_id.eq.{owner_id},is_global.eq.true)&order=title.asc&select=id,title,content,tags,is_global,owner_id",
            headers=SB_HEADERS()
        )
    else:
        import re as _re

        STOPWORDS = {'what','is','the','for','an','a','of','on','to','in','do','i','my',
                     'how','does','which','are','and','or','with','use','need','can','get',
                     'have','has','that','this','at','it','its','by','be','was','used',
                     'tell','me','about','give','find','show','should','when','where',
                     'will','would','could','should','if','then','so','but','not'}

        # Simple stemmer — strip common suffixes
        def stem(w):
            for suffix in ('ing','tion','ions','ings','ers','ed','es','s'):
                if w.endswith(suffix) and len(w) - len(suffix) >= 3:
                    return w[:-len(suffix)]
            return w

        # Synonym map — expand each keyword with related terms
        SYNONYMS = {
            'thread': ['thread','threading','pitch','muzzle','threaded'],
            'pitch': ['pitch','thread','threading'],
            'glock': ['glock','g17','g19','g20','g21','g26','g43'],
            '9mm': ['9mm','9x19','parabellum','9 mm'],
            '45': ['45','45acp','45 acp','1911'],
            'ar': ['ar','ar15','ar-15','m4','m16','223','556','5.56'],
            'aks': ['ak','ak47','ak-47','7.62'],
            'nics': ['nics','background','background check','check'],
            '4473': ['4473','form 4473','atf form'],
            'denied': ['denied','denial','denied transfer','delay','delayed'],
            'sot': ['sot','dealer','class 3','nfa','class iii'],
            'suppressor': ['suppressor','silencer','nfa','form 4','tax stamp'],
            'pistol': ['pistol','handgun','semi-auto'],
            'rifle': ['rifle','long gun','carbine'],
            'shotgun': ['shotgun','long gun','gauge'],
            'serial': ['serial','serial number','s/n'],
            'ffl': ['ffl','license','licensed dealer','federal firearms'],
            'atf': ['atf','bureau','alcohol tobacco'],
            'transfer': ['transfer','sale','sold','transferor'],
            'buyer': ['buyer','purchaser','transferee'],
        }

        # Extract and expand keywords
        raw_words = [w for w in _re.sub(r'[^a-z0-9]', ' ', query.lower()).split()
                     if len(w) > 1 and w not in STOPWORDS]
        stemmed = [stem(w) for w in raw_words]

        # Build expanded search terms
        search_terms = set()
        for w in raw_words + stemmed:
            search_terms.add(w)
            for syn_key, syn_list in SYNONYMS.items():
                if w == syn_key or w in syn_list:
                    search_terms.update(syn_list)

        search_terms = list(search_terms) if search_terms else [query]

        # Fetch candidates via ilike on each term — union with dedup
        seen_ids = set()
        candidates = []
        for term in search_terms:
            like_q = f"%{term}%"
            r2 = requests.get(
                f"{SB_URL}/rest/v1/knowledge_base?or=(owner_id.eq.{owner_id},is_global.eq.true)"
                f"&or=(title.ilike.{requests.utils.quote(like_q)},content.ilike.{requests.utils.quote(like_q)},tags.ilike.{requests.utils.quote(like_q)})"
                f"&select=id,title,content,tags,is_global,owner_id&order=title.asc",
                headers=SB_HEADERS()
            )
            for entry in (r2.json() if r2.status_code == 200 else []):
                if entry['id'] not in seen_ids:
                    seen_ids.add(entry['id'])
                    candidates.append(entry)

        # Fallback: raw query ilike if nothing found
        if not candidates:
            like_q = f"%{query}%"
            r3 = requests.get(
                f"{SB_URL}/rest/v1/knowledge_base?or=(owner_id.eq.{owner_id},is_global.eq.true)"
                f"&or=(title.ilike.{requests.utils.quote(like_q)},content.ilike.{requests.utils.quote(like_q)})"
                f"&select=id,title,content,tags,is_global,owner_id&order=title.asc",
                headers=SB_HEADERS()
            )
            candidates = r3.json() if r3.status_code == 200 else []

        # Score each result — count how many search terms appear in title+content+tags
        def score_entry(entry):
            haystack = ' '.join([
                (entry.get('title') or '').lower(),
                (entry.get('content') or '').lower(),
                (entry.get('tags') or '').lower()
            ])
            # Title matches worth 3x, content/tags 1x
            title_hay = (entry.get('title') or '').lower()
            score = 0
            for term in search_terms:
                if term in title_hay:
                    score += 3
                elif term in haystack:
                    score += 1
            # Bonus for original raw keywords matching
            for w in raw_words:
                if w in title_hay:
                    score += 2
            return score

        scored = [(score_entry(e), e) for e in candidates]
        scored.sort(key=lambda x: -x[0])
        results = [e for _, e in scored]

        return jsonify({"results": results, "query": query, "keywords": raw_words})

    results = r.json() if r.status_code == 200 else []
    return jsonify({"results": results, "query": query})


@app.route("/kb/entries", methods=["GET", "OPTIONS"])
def kb_list():
    """List all entries for owner management view."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    r = requests.get(
        f"{SB_URL}/rest/v1/knowledge_base?owner_id=eq.{owner['id']}&order=title.asc&select=id,title,content,tags,created_at,updated_at",
        headers=SB_HEADERS()
    )
    entries = r.json() if r.status_code == 200 else []
    return jsonify({"entries": entries})


@app.route("/kb/save", methods=["POST", "OPTIONS"])
def kb_save():
    """Create or update a knowledge base entry (owner only)."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    entry_id = data.get("id")
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()
    tags = (data.get("tags") or "").strip()

    if not title or not content:
        return jsonify({"error": "Title and content required"}), 400

    payload = {
        "owner_id": owner["id"],
        "title": title,
        "content": content,
        "tags": tags,
        "is_global": False
    }

    if entry_id:
        r = requests.patch(
            f"{SB_URL}/rest/v1/knowledge_base?id=eq.{entry_id}&owner_id=eq.{owner['id']}",
            headers={**SB_HEADERS(), "Prefer": "return=representation"},
            json=payload
        )
    else:
        r = requests.post(
            f"{SB_URL}/rest/v1/knowledge_base",
            headers={**SB_HEADERS(), "Prefer": "return=representation"},
            json=payload
        )

    if r.status_code not in [200, 201]:
        return jsonify({"error": "Failed to save entry", "detail": r.text}), 500

    saved = r.json()
    return_id = saved[0]["id"] if saved else entry_id
    return jsonify({"success": True, "id": return_id})


@app.route("/kb/delete", methods=["POST", "OPTIONS"])
def kb_delete():
    """Delete a knowledge base entry (owner only)."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err

    data = request.get_json()
    entry_id = data.get("id")
    if not entry_id:
        return jsonify({"error": "id required"}), 400

    requests.delete(
        f"{SB_URL}/rest/v1/knowledge_base?id=eq.{entry_id}&owner_id=eq.{owner['id']}",
        headers=SB_HEADERS()
    )
    return jsonify({"success": True})


@app.route("/save-ffl-expiration", methods=["POST", "OPTIONS"])
def save_ffl_expiration():
    """Save FFL expiration date for the owner's profile."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    owner, err = require_owner(token)
    if err:
        return err
    data = request.get_json()
    exp_date = data.get("ffl_expiration_date", "")
    # Validate date format YYYY-MM-DD or empty string to clear
    if exp_date:
        import re as _re
        if not _re.match(r"^\d{4}-\d{2}-\d{2}$", exp_date):
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400
    update_val = exp_date if exp_date else None
    r = requests.patch(
        f"{SB_URL}/rest/v1/profiles?id=eq.{owner['id']}",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        },
        json={"ffl_expiration_date": update_val}
    )
    if r.status_code not in [200, 204]:
        return jsonify({"error": "Failed to save expiration date"}), 500
    return jsonify({"success": True})


@app.route("/get-ffl-expiration", methods=["GET", "OPTIONS"])
def get_ffl_expiration():
    """Get FFL expiration date from profile."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401
    # Get owner_id — works for both owners and staff
    owner_id = get_owner_id(user["id"])
    r = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{owner_id}&select=ffl_expiration_date",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    data = r.json()
    exp_date = data[0].get("ffl_expiration_date") if data else None
    return jsonify({"ffl_expiration_date": exp_date})


@app.route("/submit-feedback", methods=["POST", "OPTIONS"])
def submit_feedback():
    """Submit support request or feature idea."""
    if request.method == "OPTIONS":
        return _cors_ok()
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    if not user or "id" not in user:
        return jsonify({"error": "Invalid session"}), 401

    data = request.get_json()
    fb_type = data.get("type", "")
    message = (data.get("message") or "").strip()

    if fb_type not in ("support", "feature"):
        return jsonify({"error": "type must be 'support' or 'feature'"}), 400
    if not message:
        return jsonify({"error": "message is required"}), 400
    if len(message) > 2000:
        return jsonify({"error": "message too long (2000 chars max)"}), 400

    # Get user email for context
    user_email = user.get("email", "")

    # Insert into feedback table using service key
    r = requests.post(
        f"{SB_URL}/rest/v1/feedback",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        },
        json={
            "user_id": user["id"],
            "type": fb_type,
            "message": message,
            "user_email": user_email,
            "status": "new"
        }
    )
    if r.status_code not in [200, 201, 204]:
        return jsonify({"error": "Failed to submit feedback"}), 500

    return jsonify({"success": True})


@app.route("/track-visit", methods=["POST", "OPTIONS"])
def track_visit():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data = request.get_json(silent=True) or {}
    page_path = data.get("page_path", "/")
    referrer = data.get("referrer", "")
    user_agent = data.get("user_agent", "")
    auth_token = data.get("auth_token", "")

    # Get real IP - respect X-Forwarded-For from Netlify/proxies
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip_address and "," in ip_address:
        ip_address = ip_address.split(",")[0].strip()

    account_email = None
    owner_email = None

    # If user sent an auth token, resolve their identity
    if auth_token:
        try:
            user = sb_get_user(auth_token)
            if user:
                account_email = user.get("email", "")
                user_id = user.get("id", "")
                # Check if this is a sub-user - look up their owner
                r = requests.get(
                    f"{SB_URL}/rest/v1/sub_users?user_id=eq.{user_id}&select=owner_id",
                    headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
                )
                if r.status_code == 200 and r.json():
                    owner_id = r.json()[0].get("owner_id")
                    if owner_id:
                        ro = requests.get(
                            f"{SB_URL}/rest/v1/profiles?id=eq.{owner_id}&select=email",
                            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
                        )
                        if ro.status_code == 200 and ro.json():
                            owner_email = ro.json()[0].get("email", "")
        except Exception:
            pass

    requests.post(
        f"{SB_URL}/rest/v1/site_visits",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        },
        json={
            "ip_address": ip_address,
            "page_path": page_path,
            "referrer": referrer,
            "user_agent": user_agent,
            "account_email": account_email,
            "owner_email": owner_email
        }
    )
    return jsonify({"ok": True})


@app.route("/admin/visitors", methods=["GET", "OPTIONS"])
def admin_visitors():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        return jsonify({"error": "Unauthorized"}), 401

    # Aggregate visits per IP with page counts, first/last seen
    r = requests.get(
        f"{SB_URL}/rest/v1/site_visits?select=ip_address,page_path,account_email,owner_email,visited_at&order=visited_at.desc&limit=5000",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    if r.status_code != 200:
        return jsonify({"error": "Failed to load visits"}), 500

    visits = r.json()

    # Load ip_labels
    rl = requests.get(
        f"{SB_URL}/rest/v1/ip_labels?select=ip_address,label,notes",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    labels = {}
    if rl.status_code == 200:
        for row in rl.json():
            labels[row["ip_address"]] = {"label": row["label"], "notes": row.get("notes", "")}

    # Aggregate by IP
    ip_data = {}
    for v in visits:
        ip = v["ip_address"]
        if ip not in ip_data:
            ip_data[ip] = {
                "ip_address": ip,
                "visit_count": 0,
                "pages": {},
                "first_seen": v["visited_at"],
                "last_seen": v["visited_at"],
                "account_email": v.get("account_email"),
                "owner_email": v.get("owner_email")
            }
        ip_data[ip]["visit_count"] += 1
        page = v["page_path"]
        ip_data[ip]["pages"][page] = ip_data[ip]["pages"].get(page, 0) + 1
        if v["visited_at"] < ip_data[ip]["first_seen"]:
            ip_data[ip]["first_seen"] = v["visited_at"]
        if v["visited_at"] > ip_data[ip]["last_seen"]:
            ip_data[ip]["last_seen"] = v["visited_at"]
        # Keep most recent account/owner info
        if v.get("account_email") and not ip_data[ip]["account_email"]:
            ip_data[ip]["account_email"] = v["account_email"]
        if v.get("owner_email") and not ip_data[ip]["owner_email"]:
            ip_data[ip]["owner_email"] = v["owner_email"]

    result = []
    for ip, d in ip_data.items():
        d["pages"] = [{"path": k, "count": v} for k, v in sorted(d["pages"].items(), key=lambda x: -x[1])]
        d["label"] = labels.get(ip, {}).get("label", "")
        d["notes"] = labels.get(ip, {}).get("notes", "")
        result.append(d)

    # Sort by last_seen desc
    result.sort(key=lambda x: x["last_seen"], reverse=True)

    # Summary stats
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    today = now.date()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    def parse_dt(s):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return now

    all_visits_today = sum(1 for v in visits if parse_dt(v["visited_at"]).date() == today)
    all_visits_week = sum(1 for v in visits if parse_dt(v["visited_at"]) >= week_ago)
    all_visits_month = sum(1 for v in visits if parse_dt(v["visited_at"]) >= month_ago)

    return jsonify({
        "visitors": result,
        "stats": {
            "total_ips": len(result),
            "visits_today": all_visits_today,
            "visits_week": all_visits_week,
            "visits_month": all_visits_month
        }
    })


@app.route("/admin/label-ip", methods=["POST", "OPTIONS"])
def admin_label_ip():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    ip_address = data.get("ip_address", "").strip()
    label = data.get("label", "").strip()
    notes = data.get("notes", "").strip()

    if not ip_address:
        return jsonify({"error": "ip_address required"}), 400

    if not label:
        # Delete label
        requests.delete(
            f"{SB_URL}/rest/v1/ip_labels?ip_address=eq.{ip_address}",
            headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
        )
        return jsonify({"ok": True})

    # Upsert
    r = requests.post(
        f"{SB_URL}/rest/v1/ip_labels",
        headers={
            "apikey": SB_SERVICE_KEY,
            "Authorization": f"Bearer {SB_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal"
        },
        json={"ip_address": ip_address, "label": label, "notes": notes, "updated_at": "now()"}
    )
    if r.status_code not in [200, 201, 204]:
        return jsonify({"error": "Failed to save label"}), 500
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8247))
    app.run(host="0.0.0.0", port=port)
