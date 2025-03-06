# 🚀 Security Headers Checker

A Python script that checks **security headers** for websites, including **Google Cloud Identity-Aware Proxy (IAP)** or any webapp behind WAF protection.

---

## 📌 Features

✅ **Security Headers Analysis** – Checks for **CSP, HSTS, X-Frame-Options**, and more.  
✅ **Supports IAP Authentication** – Uses **Selenium** to log in to **IAP-protected websites**.  
✅ **Handles Redirects** – Prevents **infinite loops** when websites redirect.  
✅ **Customizable Output** – Displays results as **tables** or **simple text**.  
✅ **Command-Line Interface (CLI)** – Easily specify **URLs and authentication options**.  

---

## 🛠 Installation

### 1️⃣ Install Dependencies
Make sure you have **Python 3.8+** installed. Then run:
```bash
pip install -r requirements.txt

pip install requests selenium colorama tabulate argparse requests

Usage 
python3 security_headers_check.py -URL compare-me.dgleb.com   
python3 security_headers_check.py --IAP -URL compare-me.dgleb.com   #For IAP protected webapps or any webapp behind a login page


