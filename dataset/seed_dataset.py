import os
import csv
import random

os.makedirs("dataset", exist_ok=True)
CSV_FILE = os.path.join("dataset", "phishing_emails.csv")

# Templates and vocabulary components for realistic dataset generation
PHISHING_TEMPLATES = [
    # Credential Harvesting / Account Suspension
    {
        "sender": "security-alert@{domain}",
        "subject": "Urgent: Your {service} account has been suspended",
        "body": "Dear customer,\n\nWe detected suspicious unauthorized login attempts on your {service} account from IP address 185.220.101.4.\n\nFor your security, access has been temporarily restricted. Please verify your identity immediately to restore access:\n\n{url}\n\nFailure to verify within 24 hours will lead to permanent account termination.\n\nSecurity Operations Team",
        "services": ["PayPal", "Microsoft 365", "Apple ID", "Netflix", "Chase Bank", "Wells Fargo", "Bank of America", "Google Workspace", "Amazon Web Services"],
        "domains": ["security-notice-update.com", "verify-account-portal.net", "auth-check-service.org", "online-banking-alerts.co", "secure-client-login.info", "account-review-center.com"],
        "url_patterns": ["http://{domain}/verify-login", "http://{domain}/account/auth?id={rand}", "http://192.168.1.104/secure/signin", "https://bit.ly/3xAuthSecure", "http://login-{service_slug}.com/credential-update"]
    },
    # Urgent Password Expiry
    {
        "sender": "it-helpdesk@{domain}",
        "subject": "ACTION REQUIRED: Your {service} password expires in 2 hours",
        "body": "Attention Employee,\n\nYour {service} network login password will expire today. To avoid disruption to your corporate email, VPN, and SSO access, click the link below to keep your current credentials:\n\n{url}\n\nDo not share your password with anyone.\n\nCorporate IT Helpdesk",
        "services": ["Office 365", "Okta SSO", "Google Suite", "Active Directory", "Salesforce", "Slack Workspace"],
        "domains": ["corp-portal-sso.com", "it-support-tickets.net", "sso-auth-gateway.info", "corporate-verify.org"],
        "url_patterns": ["http://{domain}/password-reset", "http://login.{domain}/sso/auth", "http://45.33.32.156:8080/portal", "https://tinyurl.com/sso-update-2026"]
    },
    # Fake Invoice / Wire / Payment
    {
        "sender": "billing-notice@{domain}",
        "subject": "Invoice #{rand_num} Overdue - Immediate Payment Required",
        "body": "Hello,\n\nPlease find attached the invoice #{rand_num} for your recent purchase totaling ${amount}. If you did not authorize this transaction, dispute the charges immediately at:\n\n{url}\n\nEnter your banking credentials to cancel the pending wire transfer.\n\nBilling Department",
        "services": ["QuickBooks", "Stripe Billing", "Square", "PayPal Invoicing", "Norton Antivirus", "Geek Squad"],
        "domains": ["billing-resolve-center.com", "invoice-dispute-portal.net", "customer-refund-service.com"],
        "url_patterns": ["http://{domain}/invoice/{rand_num}/dispute", "http://{domain}/refund-claim", "http://104.244.42.1/payment-confirm", "http://pay-secure-auth.org/login"]
    },
    # Shipping / Courier Fraud
    {
        "sender": "delivery-tracking@{domain}",
        "subject": "Delivery Alert: Your package #{rand_num} could not be delivered",
        "body": "Dear recipient,\n\nYour package cannot be delivered due to an incorrect shipping address and unpaid customs fee of $2.99.\n\nUpdate your delivery address and pay the fee here:\n\n{url}\n\nYour parcel will be returned to sender if unclaimed within 48 hours.\n\nCustomer Delivery Center",
        "services": ["FedEx Express", "DHL Express", "USPS Ground", "UPS Tracking"],
        "domains": ["track-package-update.com", "delivery-customs-fee.net", "postal-service-notice.org"],
        "url_patterns": ["http://{domain}/track?num={rand_num}", "http://{domain}/redelivery-confirm", "https://is.gd/deliver_now", "http://203.0.113.88/postal/verify"]
    },
    # Tax Refund / Government
    {
        "sender": "refund-claims@{domain}",
        "subject": "Notice: Pending tax refund of ${amount} waiting for disbursement",
        "body": "Official Notification:\n\nOur records indicate you are eligible for an unclaimed tax refund of ${amount}.\n\nTo process your refund directly into your bank account, submit your tax identification and bank details online:\n\n{url}\n\nIRS Department of Revenue / Tax Disbursement",
        "services": ["IRS Treasury", "HMRC Tax Office", "Federal Tax Agency"],
        "domains": ["gov-tax-disbursement.org", "refund-tax-portal.net", "tax-rebate-verify.com"],
        "url_patterns": ["http://{domain}/tax-refund/claim", "http://198.51.100.22/claim-form", "http://{domain}/secure-ssn-validate"]
    },
    # Lottery / Prize Scam
    {
        "sender": "claims-coordinator@{domain}",
        "subject": "CONGRATULATIONS! You have won ${amount} in the Global Mega Draw",
        "body": "Dear Lucky Winner,\n\nYour email address has been selected as the grand prize winner of ${amount} in our promotional sweepstakes.\n\nTo claim your prize, click the link below immediately and enter your contact and banking credentials:\n\n{url}\n\nSecurity code: WIN-{rand_num}.\n\nClaims Department",
        "services": ["International Sweepstakes", "Global Lottery Board", "Crypto Foundation Promo"],
        "domains": ["mega-prize-claims.com", "international-winner-awards.net"],
        "url_patterns": ["http://{domain}/winner-claim?code={rand_num}", "http://{domain}/redeem-prize", "http://claim-crypto-bonus.cc/login"]
    }
]

SAFE_TEMPLATES = [
    # Team & Work Updates
    {
        "sender": "{name}@{company_domain}",
        "subject": "Sprint planning notes & roadmap update for Q{quarter}",
        "body": "Hi team,\n\nThanks everyone for the productive sync earlier today. I have attached the meeting notes and updated Jira backlog links.\n\nPlease review the tickets assigned to your sprint milestone before Wednesday's standup:\n\n{safe_url}\n\nLet me know if there are any blockers or questions.\n\nBest regards,\n{name}",
        "companies": ["acme-corp.com", "techflow.io", "datamesh.org", "cloudnative.net", "vertex-labs.com", "innovate.co"],
        "safe_urls": ["https://jira.atlassian.com/browse/PROJ-412", "https://github.com/company/repo/pull/182", "https://notion.so/acme/sprint-notes-q2", "https://docs.google.com/document/d/1aB9cDef"]
    },
    # Transactional Receipts & Notifications
    {
        "sender": "no-reply@{company_domain}",
        "subject": "Your order #{order_id} has shipped - Tracking details inside",
        "body": "Hello,\n\nGreat news! Your recent order #{order_id} has been packaged and is on its way. You can track the shipment status anytime via our portal:\n\n{safe_url}\n\nEstimated delivery date: within 3-5 business days.\n\nThank you for shopping with us!\nCustomer Care Team",
        "companies": ["amazon.com", "apple.com", "target.com", "bestbuy.com", "homedepot.com", "shopify.com"],
        "safe_urls": ["https://www.amazon.com/orders/details?id=114-9218", "https://www.apple.com/shop/order/view", "https://www.target.com/track/order-9182"]
    },
    # Calendar & Meeting Invites
    {
        "sender": "{name}@{company_domain}",
        "subject": "Invitation: Architecture Review - Phishing Defense Pipeline",
        "body": "When: Thursday, 2:00 PM - 3:00 PM EST\nWhere: Google Meet Conference Room 4B\n\nAgenda:\n1. Model evaluation metrics review\n2. Infrastructure scaling for incoming telemetry\n3. Q&A and next sprint backlog grooming\n\nVideo link: {safe_url}\n\nLooking forward to speaking then,\n{name}",
        "companies": ["enterprise.com", "cyberdefense.org", "securitycloud.io", "fintechsolutions.com"],
        "safe_urls": ["https://meet.google.com/abc-defg-hij", "https://zoom.us/j/918273645", "https://teams.microsoft.com/l/meetup-join"]
    },
    # Newsletter / Educational Content
    {
        "sender": "editor@{company_domain}",
        "subject": "Weekly Tech Digest: Modern Machine Learning Architectures in 2026",
        "body": "Welcome to this week's edition of the Tech Digest!\n\nIn this issue:\n- Advances in zero-shot classification\n- Best practices for secure REST API architectures\n- Exploring modern CSS and accessibility\n\nRead the full issue on our publication blog:\n\n{safe_url}\n\nYou can manage your subscription preferences anytime at the footer link.\n\nCheers,\nThe Editorial Board",
        "companies": ["techcrunch.com", "hackernews.digest", "arxiv-newsletter.org", "towardsdatascience.com"],
        "safe_urls": ["https://towardsdatascience.com/modern-ml-guide", "https://substack.com/post/ml-insights-2026", "https://medium.com/engineering-today/soc-tools"]
    },
    # HR & Operations
    {
        "sender": "hr-operations@{company_domain}",
        "subject": "Company Holiday Schedule & Upcoming Volunteer Day",
        "body": "Hello Everyone,\n\nPlease find the updated calendar for upcoming public holidays and our annual company volunteer day scheduled for next month.\n\nReview the employee portal guidelines:\n\n{safe_url}\n\nHave a wonderful and restful weekend!\n\nPeople & Culture Team",
        "companies": ["acme-corp.com", "innovate.co", "datamesh.org", "vertex-labs.com"],
        "safe_urls": ["https://bamboohr.com/employee/portal", "https://workday.com/acme/calendar", "https://internal.acme-corp.com/culture"]
    },
    # Routine GitHub / DevOps Notifications
    {
        "sender": "notifications@github.com",
        "subject": "[GitHub] Workflow run 'CI / Lint and Tests' succeeded on main",
        "body": "All 42 checks passed for commit e4f71a8.\n\nRepository: org/email-security-gateway\nTriggered by: pardhu-dev\nBranch: main\n\nView workflow run execution logs:\n\n{safe_url}\n\nGitHub Actions Automation",
        "companies": ["github.com"],
        "safe_urls": ["https://github.com/org/email-security-gateway/actions/runs/9876543", "https://github.com/org/email-security-gateway/pull/35"]
    }
]

NAMES = ["Sarah Jenkins", "Alex Rivera", "David Chen", "Emily Watson", "Michael Brown", "Lisa Zhang", "James Wilson", "Rachel Taylor", "Daniel Miller", "Sophia Martinez"]

BORDERLINE_SAFE = [
    {
        "sender": "support@paypal.com",
        "subject": "Receipt for your payment to Digital Services Inc",
        "body": "Hello,\n\nYou sent a payment of $32.50 USD to Digital Services Inc. Details of this transaction are available in your account.\n\nIf you have questions about this transaction or wish to review your recent payment activity, log into your account at https://www.paypal.com\n\nThanks,\nPayPal",
        "label": "safe"
    },
    {
        "sender": "account-security-noreply@accountprotection.microsoft.com",
        "subject": "Microsoft account security alert",
        "body": "Security alert for your Microsoft account.\n\nWe detected something unusual about a recent sign-in. To help keep your account secure, please review your recent activity:\n\nhttps://account.live.com/Activity\n\nThanks,\nThe Microsoft account team",
        "label": "safe"
    },
    {
        "sender": "no-reply@chase.com",
        "subject": "Your monthly Chase statement is now ready",
        "body": "Your new electronic statement is ready to view. To review your balance and transactions, sign in securely at https://www.chase.com or through your mobile app.\n\nWe will never ask you to reply with your password or PIN.\n\nChase Customer Service",
        "label": "safe"
    },
    {
        "sender": "it-support@corp-internal.com",
        "subject": "Scheduled IT Maintenance and Security Password Reminder",
        "body": "Hi team,\n\nAs part of our standard quarterly cybersecurity routine, please ensure your workstation login password meets the minimum corporate length policy. You can update your credentials via the internal Windows login settings (Ctrl+Alt+Del).\n\nNever enter your credentials on any external website.\n\nIT Support",
        "label": "safe"
    },
    {
        "sender": "billing@saasplatform.com",
        "subject": "Monthly Subscription Invoice and Payment Receipt",
        "body": "Dear valued subscriber,\n\nYour monthly subscription payment of $49.00 has been processed successfully. Your updated receipt is ready. View your billing history in your authenticated dashboard at:\n\nhttps://saasplatform.com/account/billing\n\nThank you for choosing our platform.\nCustomer Success",
        "label": "safe"
    },
    {
        "sender": "notifications@linkedin.com",
        "subject": "Urgent connection request from recruiter: Senior Security Engineer",
        "body": "Hi, a recruiter has sent you an urgent inquiry regarding an open security engineering position. View message and profile at https://www.linkedin.com/comm/messaging/thread/681\n\nLinkedIn Talent Solutions",
        "label": "safe"
    }
]

BORDERLINE_PHISHING = [
    {
        "sender": "colleague@acme-corporate-office.com",
        "subject": "Can you review this slide deck before our 2 PM call?",
        "body": "Hey, could you please take a look at the updated client proposal presentation? Let me know if the numbers look good: http://onedrive-docs-sharing.co/view/presentation\n\nThanks,\nAlex Rivera",
        "label": "phishing"
    },
    {
        "sender": "vp-finance@executive-consulting.net",
        "subject": "Quick review needed - Confidential supplier invoice",
        "body": "Hi, are you at your desk? I need you to quickly review the attached consultant invoice for our ongoing merger before 5 PM today. Review the summary document here: http://secure-doc-share-portal.cc/invoice-view\n\nPlease keep this strictly confidential.\nSent from my iPhone",
        "label": "phishing"
    },
    {
        "sender": "payroll-audit@company-benefit-portal.info",
        "subject": "Important update regarding your 2026 direct deposit",
        "body": "Good morning,\n\nThere was an issue processing your direct deposit payroll verification for the upcoming cycle. Please confirm your routing information to prevent payment delay:\n\nhttp://198.51.100.44/payroll/confirm\n\nHuman Resources / Payroll Services",
        "label": "phishing"
    },
    {
        "sender": "helpdesk@internal-sso-gateway.net",
        "subject": "Reminder: Complete single sign-on synchronization",
        "body": "All staff must synchronize their active directory single sign on profile today. Failure to synchronize will lock corporate VPN. Access synchronization page: http://sso-corporate-sync.net/login\n\nInternal IT Support",
        "label": "phishing"
    }
]

def generate_dataset(num_phishing=1250, num_safe=1250):
    random.seed(42)
    rows = []
    
    # Generate Phishing emails
    for i in range(num_phishing):
        # 10% chance of subtle borderline phishing
        if random.random() < 0.10:
            item = random.choice(BORDERLINE_PHISHING)
            rows.append({
                "sender": item["sender"],
                "subject": item["subject"],
                "body": item["body"],
                "text": f"Subject: {item['subject']}\n\n{item['body']}",
                "label": item["label"]
            })
            continue

        template = random.choice(PHISHING_TEMPLATES)
        service = random.choice(template["services"])
        service_slug = service.lower().replace(" ", "-")
        domain = random.choice(template["domains"])
        rand_num = random.randint(100000, 999999)
        rand = random.randint(1000, 9999)
        amount = f"{random.randint(45, 9500):,}.{random.randint(10, 99):02d}"
        
        url_pat = random.choice(template["url_patterns"])
        url = url_pat.format(domain=domain, service_slug=service_slug, rand=rand, rand_num=rand_num)
        
        sender = template["sender"].format(domain=domain, service=service)
        subject = template["subject"].format(service=service, rand_num=rand_num, amount=amount)
        body = template["body"].format(service=service, domain=domain, url=url, rand_num=rand_num, amount=amount)
        
        # Mix in variations: add urgent keywords, HTML styling tags
        if random.random() < 0.35:
            body = f"<html><body><p><b>URGENT SECURITY NOTIFICATION:</b></p><p>{body}</p><br><a href='{url}'>CLICK HERE IMMEDIATELY</a></body></html>"
        
        combined_text = f"Subject: {subject}\n\n{body}"
        rows.append({
            "sender": sender,
            "subject": subject,
            "body": body,
            "text": combined_text,
            "label": "phishing"
        })

    # Generate Safe emails
    for i in range(num_safe):
        # 12% chance of borderline safe emails with security/billing terms
        if random.random() < 0.12:
            item = random.choice(BORDERLINE_SAFE)
            rows.append({
                "sender": item["sender"],
                "subject": item["subject"],
                "body": item["body"],
                "text": f"Subject: {item['subject']}\n\n{item['body']}",
                "label": item["label"]
            })
            continue

        template = random.choice(SAFE_TEMPLATES)
        name = random.choice(NAMES)
        company_domain = random.choice(template["companies"])
        quarter = random.choice([1, 2, 3, 4])
        order_id = f"{random.randint(100, 999)}-{random.randint(1000000, 9999999)}"
        safe_url = random.choice(template["safe_urls"])
        
        sender = template["sender"].format(name=name.lower().replace(" ", "."), company_domain=company_domain)
        subject = template["subject"].format(name=name, quarter=quarter, order_id=order_id)
        body = template["body"].format(name=name, quarter=quarter, order_id=order_id, safe_url=safe_url)
        
        combined_text = f"Subject: {subject}\n\n{body}"
        rows.append({
            "sender": sender,
            "subject": subject,
            "body": body,
            "text": combined_text,
            "label": "safe"
        })

    # Shuffle rows
    random.shuffle(rows)
    
    # Write to CSV
    fieldnames = ["sender", "subject", "body", "text", "label"]
    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"Generated {len(rows)} emails ({num_phishing} phishing, {num_safe} safe) at {CSV_FILE}")

if __name__ == "__main__":
    generate_dataset()
