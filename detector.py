# ============================================
# Phishing Email Detector
# Author: Muhammad Atif Jan
# Student ID: 24173902
# Supervisor: Dr Lili Kirner
# University of Hertfordshire
# Module: 6WCM0029
# ============================================

while True:

    # Welcome message
    print("=" * 45)
    print("   PHISHING EMAIL DETECTOR")
    print("=" * 45)
    print("Paste the email text below then press Enter.")
    print("Type 'quit' to exit the program.")
    print("")

    # Step 1: Get email input from user
    email_text = input(">>> ").lower()

    # Check if user wants to quit
    if email_text == "quit":
        print("Exiting detector. Goodbye!")
        break

    # Step 2: Set up score and triggered list
    score = 0
    triggered = []

    print("")
    print("Analysing email...")
    print("")

    # ============================================
    # RULE 1: Urgency Language
    # Attackers use urgent language to pressure
    # victims into acting without thinking.
    # Weight: 2 points
    # ============================================
    urgency_keywords = [
        "act now",
        "immediately",
        "urgent",
        "within 24 hours",
        "as soon as possible",
        "right away",
        "don't delay",
        "respond immediately",
        "time sensitive",
        "expires today"
    ]
    for keyword in urgency_keywords:
        if keyword in email_text:
            score = score + 2
            triggered.append("Rule 1 — Urgency language detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 2: Threatening Consequences
    # Legitimate organisations rarely threaten
    # legal action or account closure by email.
    # Weight: 3 points
    # ============================================
    threat_keywords = [
        "legal action",
        "account will be closed",
        "account will be suspended",
        "failure to comply",
        "will be terminated",
        "face penalties",
        "will be fined",
        "prosecuted",
        "reported to authorities"
    ]
    for keyword in threat_keywords:
        if keyword in email_text:
            score = score + 3
            triggered.append("Rule 2 — Threatening consequences detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 3: Request for Sensitive Information
    # No legitimate organisation asks for
    # passwords or card details by email.
    # Weight: 3 points
    # ============================================
    sensitive_keywords = [
        "password",
        "pin number",
        "card number",
        "credit card",
        "bank details",
        "account number",
        "social security",
        "date of birth",
        "verify your details",
        "confirm your details"
    ]
    for keyword in sensitive_keywords:
        if keyword in email_text:
            score = score + 3
            triggered.append("Rule 3 — Sensitive information request detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 4: Generic Greeting
    # Scammers send mass emails and do not know
    # the recipient's name.
    # Weight: 1 point
    # ============================================
    generic_greetings = [
        "dear customer",
        "dear user",
        "dear account holder",
        "dear member",
        "dear client",
        "to whom it may concern",
        "dear valued customer"
    ]
    for greeting in generic_greetings:
        if greeting in email_text:
            score = score + 1
            triggered.append("Rule 4 — Generic greeting detected: '" + greeting + "'")
            break

    # ============================================
    # RULE 5: Suspicious Link Indicators
    # Phishing emails trick victims into clicking
    # malicious links disguised as legitimate ones.
    # Weight: 3 points
    # ============================================
    link_keywords = [
        "click here",
        "verify your account",
        "login here",
        "click the link below",
        "follow this link",
        "click below",
        "click this link",
        "access here"
    ]
    for keyword in link_keywords:
        if keyword in email_text:
            score = score + 3
            triggered.append("Rule 5 — Suspicious link detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 6: Reward or Prize Pressure
    # Attackers exploit greed to trick victims
    # into clicking links or providing details.
    # Weight: 2 points
    # ============================================
    reward_keywords = [
        "you have won",
        "you've won",
        "claim your prize",
        "congratulations you",
        "selected as a winner",
        "claim now",
        "free gift",
        "you are entitled"
    ]
    for keyword in reward_keywords:
        if keyword in email_text:
            score = score + 2
            triggered.append("Rule 6 — Reward or prize pressure detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 7: Unexpected Attachment
    # Attachments in unexpected emails are a
    # common method for delivering malware.
    # Weight: 2 points
    # ============================================
    attachment_keywords = [
        "open the attachment",
        "see attached",
        "attached file",
        "download the file",
        "attached document",
        "open attached",
        "attached invoice",
        "attached receipt"
    ]
    for keyword in attachment_keywords:
        if keyword in email_text:
            score = score + 2
            triggered.append("Rule 7 — Unexpected attachment detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 8: Spelling and Grammar Errors
    # Phishing emails often contain unusual
    # phrasing or spelling mistakes.
    # Weight: 1 point
    # ============================================
    error_keywords = [
        "kindly do the needful",
        "revert back to us",
        "do the nessecary",
        "click bellow",
        "varify",
        "susupended",
        "immediatly",
        "passward"
    ]
    for keyword in error_keywords:
        if keyword in email_text:
            score = score + 1
            triggered.append("Rule 8 — Spelling or grammar error detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 9: Suspicious Sender Domain
    # Attackers use domains that look similar
    # to legitimate ones to deceive victims.
    # Weight: 3 points
    # ============================================
    fake_domain_keywords = [
        "paypa1",
        "amaz0n",
        "secure-bank",
        "account-alert",
        "verify-login",
        "security-alert",
        "bank-secure",
        "update-account",
        "customer-verify"
    ]
    for keyword in fake_domain_keywords:
        if keyword in email_text:
            score = score + 3
            triggered.append("Rule 9 — Suspicious sender domain detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 10: Urgency Combined with Security Alert
    # Combining urgency with security warnings
    # is a classic phishing tactic.
    # Weight: 2 points
    # ============================================
    combined_keywords = [
        "urgent action required",
        "immediate response required",
        "your account has been compromised",
        "security breach detected",
        "unusual activity detected",
        "suspicious activity"
    ]
    for keyword in combined_keywords:
        if keyword in email_text:
            score = score + 2
            triggered.append("Rule 10 — High urgency security alert detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 11: URL Shortener Detection
    # Shortened URLs hide the real destination
    # and are commonly used in phishing attacks.
    # Weight: 2 points
    # ============================================
    url_shorteners = [
        "bit.ly",
        "tinyurl",
        "t.co",
        "goo.gl",
        "ow.ly",
        "shorturl",
        "tiny.cc",
        "is.gd",
        "buff.ly"
    ]
    for keyword in url_shorteners:
        if keyword in email_text:
            score = score + 2
            triggered.append("Rule 11 — URL shortener detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 12: Brand Impersonation
    # Attackers impersonate trusted brands to
    # make emails appear legitimate.
    # Weight: 3 points
    # ============================================
    brand_keywords = [
        "paypal",
        "amazon",
        "netflix",
        "microsoft",
        "apple",
        "google",
        "hsbc",
        "barclays",
        "halifax",
        "natwest",
        "facebook",
        "instagram",
        "dhl",
        "fedex",
        "ups"
    ]
    for keyword in brand_keywords:
        if keyword in email_text:
            score = score + 3
            triggered.append("Rule 12 — Brand impersonation detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 13: OTP or Verification Code Request
    # Legitimate services never ask for OTP
    # or security codes via email.
    # Weight: 3 points
    # ============================================
    otp_keywords = [
        "one time password",
        "otp",
        "verification code",
        "security code",
        "authentication code",
        "confirm your code",
        "enter the code",
        "2fa code",
        "two factor"
    ]
    for keyword in otp_keywords:
        if keyword in email_text:
            score = score + 3
            triggered.append("Rule 13 — OTP or verification code request detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 14: Threatening Deadline
    # Creating artificial deadlines pressures
    # victims into acting without thinking.
    # Weight: 2 points
    # ============================================
    deadline_keywords = [
        "today only",
        "expires tonight",
        "last chance",
        "final warning",
        "final notice",
        "limited time",
        "offer expires",
        "deadline today",
        "respond today"
    ]
    for keyword in deadline_keywords:
        if keyword in email_text:
            score = score + 2
            triggered.append("Rule 14 — Threatening deadline detected: '" + keyword + "'")
            break

    # ============================================
    # RULE 15: Confidentiality Request
    # Asking recipients to keep emails secret
    # is unusual in legitimate communication.
    # Weight: 2 points
    # ============================================
    confidential_keywords = [
        "do not share",
        "keep this confidential",
        "do not forward",
        "delete this email after",
        "confidential message",
        "do not reply to this email",
        "for your eyes only"
    ]
    for keyword in confidential_keywords:
        if keyword in email_text:
            score = score + 2
            triggered.append("Rule 15 — Confidentiality request detected: '" + keyword + "'")
            break

    # ============================================
    # OUTPUT: Display results to user
    # ============================================
    print("=" * 45)
    print("   PHISHING DETECTION RESULTS")
    print("=" * 45)
    print("")

    # Step 3: Classify risk based on total score
    if score <= 3:
        risk_level = "LOW RISK"
    elif score <= 7:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "HIGH RISK"

    print("Total Score : " + str(score))
    print("Risk Level  : " + risk_level)
    print("")

    if len(triggered) == 0:
        print("No phishing indicators detected.")
    else:
        print("Indicators detected:")
        for item in triggered:
            print("  - " + item)

    print("")
    print("=" * 45)
    print("")