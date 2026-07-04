# Phishing Email Detector
# Author: Muhammad Atif Jan
# Student ID: 24173902

# Step 1: Get the email text from the user
print("=== Phishing Email Detector ===")
print("Paste the email text below, then press Enter twice:")
print("")

lines = []
while True:
    line = input()
    if line == "":
        break
    lines.append(line)

email_text = " ".join(lines).lower()
score = 0
triggered = []

print("")
print("Analysing email...")
print("")


# Rule 1: Urgency Language (Weight: 2 points)
urgency_keywords = [
    "act now", "immediately", "urgent", "within 24 hours",
    "as soon as possible", "right away", "don't delay",
    "respond immediately", "time sensitive", "expires today"
]

for keyword in urgency_keywords:
    if keyword in email_text:
        score = score + 2
        triggered.append("Urgency language detected ('" + keyword + "')")
        break

    # Rule 2: Threatening Consequences (Weight: 3 points)
threat_keywords = [
    "legal action", "account will be closed", "account will be suspended",
    "failure to comply", "will be terminated", "face penalties",
    "will be fined", "prosecuted", "reported to authorities"
]

for keyword in threat_keywords:
    if keyword in email_text:
        score = score + 3
        triggered.append("Threatening consequences detected ('" + keyword + "')")
        break

# Rule 3: Request for Sensitive Information (Weight: 3 points)
sensitive_keywords = [
    "password", "pin number", "card number", "credit card",
    "bank details", "account number", "social security",
    "date of birth", "verify your details", "confirm your details"
]

for keyword in sensitive_keywords:
    if keyword in email_text:
        score = score + 3
        triggered.append("Request for sensitive information detected ('" + keyword + "')")
        break

# Rule 4: Generic Greeting (Weight: 1 point)
generic_greetings = [
    "dear customer", "dear user", "dear account holder",
    "dear member", "dear client", "to whom it may concern",
    "dear valued customer"
]

for greeting in generic_greetings:
    if greeting in email_text:
        score = score + 1
        triggered.append("Generic greeting detected ('" + greeting + "')")
        break

# Rule 5: Suspicious Link Indicators (Weight: 3 points)
link_keywords = [
    "click here", "verify your account", "login here",
    "click the link below", "follow this link", "click below",
    "click this link", "access here"
]

for keyword in link_keywords:
    if keyword in email_text:
        score = score + 3
        triggered.append("Suspicious link or action detected ('" + keyword + "')")
        break

    # Rule 6: Reward or Prize Pressure (Weight: 2 points)
reward_keywords = [
    "you have won", "you've won", "claim your prize",
    "congratulations you", "selected as a winner",
    "claim now", "free gift", "you are entitled"
]

for keyword in reward_keywords:
    if keyword in email_text:
        score = score + 2
        triggered.append("Reward or prize pressure detected ('" + keyword + "')")
        break

# Rule 7: Unexpected Attachment (Weight: 2 points)
attachment_keywords = [
    "open the attachment", "see attached", "attached file",
    "download the file", "attached document", "open attached",
    "attached invoice", "attached receipt"
]

for keyword in attachment_keywords:
    if keyword in email_text:
        score = score + 2
        triggered.append("Unexpected attachment reference detected ('" + keyword + "')")
        break

# Rule 8: Spelling and Grammar Errors (Weight: 1 point)
error_keywords = [
    "kindly do the needful", "revert back to us",
    "do the nessecary", "click bellow", "varify",
    "account", "susupended", "immediatly", "passward"
]

for keyword in error_keywords:
    if keyword in email_text:
        score = score + 1
        triggered.append("Spelling or grammar error detected ('" + keyword + "')")
        break

# Rule 9: Sender Address Inconsistency (Weight: 3 points)
fake_domain_keywords = [
    "paypa1", "amaz0n", "secure-bank", "account-alert",
    "verify-login", "security-alert", "bank-secure",
    "update-account", "customer-verify"
]

for keyword in fake_domain_keywords:
    if keyword in email_text:
        score = score + 3
        triggered.append("Suspicious sender domain detected ('" + keyword + "')")
        break

# Rule 10: Urgency Combined with Unusual Formatting (Weight: 2 points)
combined_keywords = [
    "urgent action required", "immediate response required",
    "your account has been compromised", "security breach detected",
    "unusual activity detected", "suspicious activity"
]

for keyword in combined_keywords:
    if keyword in email_text:
        score = score + 2
        triggered.append("High-urgency security alert language detected ('" + keyword + "')")
        break

# ── OUTPUT SECTION ──
print("=" * 45)
print("PHISHING DETECTION RESULTS")
print("=" * 45)
print("")

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