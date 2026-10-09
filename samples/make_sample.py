"""Generates samples/sample_phish.eml (harmless: the 'exe' is just an MZ header stub)."""
from email.message import EmailMessage
m = EmailMessage()
m["From"] = '"PayPal Security" <service@paypa1-secure.top>'
m["To"] = "victim@example.org"
m["Reply-To"] = "collect@mailbox-drop.xyz"
m["Return-Path"] = "<bounce@bulk-sender.tk>"
m["Subject"] = "URGENT: Your account has been suspended - immediate action required"
m["Date"] = "Tue, 29 Sep 2026 10:15:00 +0000"
m["Message-ID"] = "<abc123@paypa1-secure.top>"
m["Received"] = "from mx.example.org (mx.example.org [10.0.0.5]) by inbox.example.org with LMTP; Tue, 29 Sep 2026 10:15:07 +0000"
m["Received"] = "from mail.paypa1-secure.top (mail.paypa1-secure.top [45.33.32.156]) by mx.example.org with ESMTP; Tue, 29 Sep 2026 10:15:05 +0000"
m["Authentication-Results"] = "mx.example.org; spf=fail smtp.mailfrom=bulk-sender.tk; dkim=none; dmarc=fail header.from=paypa1-secure.top"
m.set_content("Your account has been suspended. Verify your account now: https://paypa1-secure.top/login")
m.add_alternative('<p>Dear customer, <a href="https://evil-login.tk/steal">https://www.paypal.com/verify</a></p>'
                  '<div style="display:none"><a href="http://198.51.100.9/track">x</a></div>', subtype="html")
m.add_attachment(b"MZ" + b"\x90\x00" * 64, maintype="application", subtype="pdf", filename="Invoice_9931.pdf.exe")
m.add_attachment(b"MZ" + b"\x00" * 64, maintype="application", subtype="pdf", filename="statement.pdf")
open("samples/sample_phish.eml", "wb").write(bytes(m))
