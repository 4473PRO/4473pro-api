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

import stripe

SB_URL = os.environ.get("SUPABASE_URL")
SB_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
ENCRYPTION_KEY = bytes.fromhex(os.environ.get("ENCRYPTION_KEY", "0" * 64))
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")

# 4473 Pro product IDs — ignore all other Stripe products (e.g. Teachable)
VALID_PRODUCT_IDS = {"prod_U5zaGkcmpaayRM", "prod_U5zrlcGBf3n0V0"}

SYSTEM_PROMPT = """You are an expert ATF Form 4473 compliance auditor with deep knowledge of federal firearms regulations, ATF instructions, and Gun Control Act requirements. Your job is to carefully examine each Form 4473 and any supporting documents provided, then produce a thorough compliance audit report.

AUDIT SECTIONS:
Examine every field in Sections A, B, C, D, and E of the Form 4473 (August 2023 revision, mandatory since February 2024).

VERDICT DEFINITIONS — USE EXACTLY ONE AT THE END:
- APPROVED: Zero issues found anywhere. Every field complete, accurate, and compliant.
- REQUIRES CORRECTION: Any issue, discrepancy, missing field, or flag was found — even minor ones.
- DO NOT TRANSFER: Buyer is prohibited, NICS was denied, or a legal disqualifier is present.

CRITICAL VERDICT RULES:
- NEVER revise your verdict. State it once at the end, correctly the first time.
- If you mention ANY issue, flag, discrepancy, or correction anywhere in your report — the verdict MUST be REQUIRES CORRECTION, not APPROVED.
- APPROVED means absolutely zero flags or issues anywhere in the entire report.
- Only DO NOT TRANSFER for actual legal disqualifiers: prohibited person, denied NICS, underage buyer, or "Yes" answer to Q21.b or Q21.n.

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

OUT-OF-STATE ID RULES:
- For LONG GUN transfers: an out-of-state ID is fully acceptable. Federal law permits long gun transfers to residents of any state. Do NOT flag out-of-state IDs or require supplemental documentation for long gun transfers.
- For HANDGUN transfers: the buyer must be a resident of the FFL's state. If the ID shows a different state than the FFL's state, flag this as REQUIRES CORRECTION.

SECTION A — FIREARM DESCRIPTION RULES:
- Q1 Manufacturer/Importer: For imported firearms, BOTH the foreign manufacturer AND the U.S. importer must be listed (e.g., "HS Produkt / Springfield Armory"). If only one is recorded for an imported firearm, flag as REQUIRES CORRECTION.
- Q1 Privately Made Firearm (PMF): If the firearm is a PMF, it must be identified as such in Q1. PMFs must be marked with the FFL's abbreviated license number as a prefix before transfer.
- Q2 Model, Q3 Serial Number, Q4 Type, Q5 Caliber/Gauge: All must be present and complete. A missing or blank serial number is only acceptable for certain pre-1968 firearms (record "NSN" or "None Visible"). Flag any other blank serial number.
- Serial number transcription: If a disposition receipt is present, verify the serial number on the 4473 matches exactly. Transposed digits or character substitutions (0 vs O, 1 vs l) are REQUIRES CORRECTION.

SECTION B — BUYER ELIGIBILITY RULES:
- Q10 Address: Must be a physical residential address, not a P.O. Box. Flag P.O. Box addresses as REQUIRES CORRECTION.
- Q10 "Reside in City Limits": This checkbox is required on the current (August 2023) form revision. If it is blank or unanswered, flag as REQUIRES CORRECTION.
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
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=subscription_status,state,business_name,onboarding_completed,ccw_exempt,ccw_permit_name,bgcheck_system,delayed_transfer_rule,q32_notation_patterns,pawn_shop_mode,sot_dealer,custom_rules",
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
        # Check if it's a 4473 Pro product
        stripe.api_key = STRIPE_SECRET_KEY
        try:
            items = stripe.checkout.Session.list_line_items(data["id"])
            is_4473 = False
            for item in items.data:
                price = stripe.Price.retrieve(item.price.id, expand=["product"])
                product_id = price.product.id if hasattr(price.product, 'id') else price.product
                if product_id in VALID_PRODUCT_IDS:
                    is_4473 = True
                    break
            if not is_4473:
                return jsonify({"status": "not a 4473 Pro product"}), 200
        except Exception:
            pass

        # Try to update existing user, or create new one
        updated = set_subscription_status(email, "active", customer_id, subscription_id)
        if not updated:
            create_supabase_user(email, customer_id, subscription_id)

    elif event_type == "invoice.paid":
        email = data.get("customer_email", "")
        customer_id = data.get("customer", "")
        subscription_id = data.get("subscription", "")
        if not email:
            return jsonify({"status": "no email"}), 200
        # Check product
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
                        bgcheck_system=None, delayed_transfer_rule=None,
                        q32_notation_patterns=None, pawn_shop_mode=False,
                        sot_dealer=False, custom_rules=None):
    prompt = SYSTEM_PROMPT

    # Background check system
    bgcheck = (bgcheck_system or 'NICS').strip().upper()
    if bgcheck != 'NICS':
        prompt += (
            f"\n\nBACKGROUND CHECK SYSTEM: This FFL uses {bgcheck} (not NICS) as their state "
            f"point of contact for background checks. All references to 'NICS' in your audit "
            f"should be interpreted as '{bgcheck}'. The NTN field will contain a {bgcheck} "
            f"transaction number — treat it identically to an NTN."
        )

    # Delayed transfer rule
    delay_rule = (delayed_transfer_rule or 'default_proceed').strip()
    if delay_rule == 'approval_required':
        prompt += (
            f"\n\nDELAYED TRANSFER RULE — STATE-SPECIFIC: In this FFL's state, a 'Delayed' "
            f"{bgcheck} response does NOT generate a 'can transfer by' date. The FFL must "
            f"wait for an explicit APPROVAL before transferring. Do NOT flag the absence of "
            f"a 'can transfer by' date on delayed transfers — it is not required here. "
            f"Only flag if the form shows a transfer was completed while status was still "
            f"'Delayed' without a documented approval."
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
    if ccw_exempt and ccw_permit_name:
        prompt += (
            f"\n\nSTATE-SPECIFIC RULE — CCW {bgcheck} EXEMPTION: This FFL's state allows "
            f"firearm transfers without a {bgcheck} background check when the buyer presents "
            f"a valid concealed carry permit. The permit name is: {ccw_permit_name}. "
            f"If a valid {ccw_permit_name} is documented, Section C {bgcheck} fields are "
            f"N/A — do not flag them as missing. The permit must have been issued within "
            f"the last 5 years to qualify."
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
    update_data = {
        "onboarding_completed": True,
        "business_name": body.get("business_name", ""),
        "ffl_number": body.get("ffl_number", ""),
        "phone": body.get("phone", ""),
        "state": body.get("state", ""),
        "monthly_transfers": body.get("monthly_transfers", ""),
    }

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

    ccw_exempt = profile.get("ccw_exempt", False)
    ccw_permit_name = profile.get("ccw_permit_name", "")
    business_name = profile.get("business_name", "")
    system_prompt = build_system_prompt(
        ccw_exempt=ccw_exempt,
        ccw_permit_name=ccw_permit_name,
        business_name=business_name,
        bgcheck_system=profile.get("bgcheck_system", "NICS"),
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
            "anthropic-version": "2023-06-01"
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 4096,
            "system": system_prompt,
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
        "bgcheck_system", "delayed_transfer_rule", "q32_notation_patterns",
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
        f"{SB_URL}/rest/v1/profiles?select=id,email,subscription_status,business_name,state,ffl_number,stripe_customer_id,stripe_subscription_id,created_by_admin,cancelled_at,created_at,bgcheck_system,delayed_transfer_rule,q32_notation_patterns,pawn_shop_mode,sot_dealer,ccw_exempt,ccw_permit_name,custom_rules,admin_notes&order=created_at.desc",
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
    success = create_supabase_user(email, None, None)
    if not success:
        return jsonify({"error": "Failed to create account — email may already exist"}), 400

    # Set admin_notes and created_by_admin flag
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
            json={"created_by_admin": True, "admin_notes": admin_notes}
        )

    return jsonify({"success": True, "email": email})


@app.route("/admin/update-account/<user_id>", methods=["POST", "OPTIONS"])
def admin_update_account(user_id):
    """Admin updates account fields (subscription status, admin notes, compliance profile)."""
    if request.method == "OPTIONS":
        return "", 200
    if not verify_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json()
    allowed = [
        "subscription_status", "admin_notes", "bgcheck_system", "delayed_transfer_rule",
        "q32_notation_patterns", "pawn_shop_mode", "sot_dealer", "ccw_exempt",
        "ccw_permit_name", "custom_rules"
    ]

    # Get current profile for change logging
    pr = requests.get(
        f"{SB_URL}/rest/v1/profiles?id=eq.{user_id}&select=*",
        headers={"apikey": SB_SERVICE_KEY, "Authorization": f"Bearer {SB_SERVICE_KEY}"}
    )
    profiles = pr.json()
    current = profiles[0] if profiles else {}

    update_data = {k: v for k, v in body.items() if k in allowed}
    if not update_data:
        return jsonify({"error": "No valid fields to update"}), 400

    # Log rule changes made by admin
    rule_fields = ["bgcheck_system", "delayed_transfer_rule", "q32_notation_patterns",
                   "pawn_shop_mode", "sot_dealer", "ccw_exempt", "ccw_permit_name", "custom_rules"]
    for field in rule_fields:
        if field in update_data and str(current.get(field)) != str(update_data[field]):
            log_rule_change(user_id, field, current.get(field), update_data[field], changed_by="admin")

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
        return jsonify({"error": "Update failed"}), 500
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
  "summary": "2-3 sentence plain English summary of the situation",
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
            "max_tokens": 2048,
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
    Trigger a cache refresh for all 50 states × 4 firearm types.
    Full refresh runs in a background thread and returns immediately.
    Single-entry refresh (state_code + firearm_type) runs synchronously.
    Called nightly via cron-job.org. Protected by admin secret.
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
                pass  # Individual failures are silent — cron will retry nightly
            if i < len(work) - 1:
                time.sleep(3)

    thread = threading.Thread(target=run_full_refresh, daemon=True)
    thread.start()

    return jsonify({
        "message": "Full cache refresh started in background. All 200 entries will be updated over the next 10–15 minutes. Click 'Reload Stats' to check progress.",
        "results": {"success": 0, "failed": 0, "errors": []}
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


RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

@app.route("/support", methods=["POST", "OPTIONS"])
def support():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        name          = (data.get("name") or "").strip()
        email         = (data.get("email") or "").strip()
        account_email = (data.get("account_email") or "").strip()
        subject       = (data.get("subject") or "").strip()
        message       = (data.get("message") or "").strip()

        if not name or not email or not subject or not message:
            return jsonify({"error": "Missing required fields"}), 400

        account_line = f"<tr><td style='padding:6px 0;color:#888;'>Account Email</td><td style='padding:6px 0;'>{account_email or '(same as above)'}</td></tr>"

        html_body = f"""
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#1c1a17;color:#e0d8cc;padding:32px;border-radius:6px;border-top:3px solid #D4A843;">
          <div style="font-family:monospace;font-size:1.3rem;color:#D4A843;letter-spacing:2px;margin-bottom:24px;">4473 PRO — SUPPORT REQUEST</div>
          <table style="width:100%;border-collapse:collapse;font-size:0.92rem;margin-bottom:24px;">
            <tr><td style="padding:6px 0;color:#888;width:140px;">From</td><td style="padding:6px 0;">{name} &lt;{email}&gt;</td></tr>
            {account_line}
            <tr><td style="padding:6px 0;color:#888;">Topic</td><td style="padding:6px 0;">{subject}</td></tr>
          </table>
          <div style="background:#141210;border:1px solid rgba(255,255,255,0.08);border-radius:4px;padding:20px;font-size:0.92rem;line-height:1.7;white-space:pre-wrap;">{message}</div>
          <div style="margin-top:24px;font-size:0.78rem;color:#555;">Reply directly to this email to respond to {name}.</div>
        </div>
        """

        if not RESEND_API_KEY:
            return jsonify({"error": "Email service not configured"}), 500

        r = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "from": "4473 Pro Support <support@4473pro.com>",
                "to": ["info@4473pro.com"],
                "reply_to": email,
                "subject": f"[Support] {subject} — {name}",
                "html": html_body
            }
        )

        if r.status_code in [200, 201]:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Failed to send email"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8247))
    app.run(host="0.0.0.0", port=port)
