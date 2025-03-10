# 🚀 Security Headers Checker

A Python script that checks **security headers** for websites, including **Google Cloud Identity-Aware Proxy (IAP)** or any webapp behind WAF protection.

---

## 📌 Features

- Check security headers of any website
- Support for protected sites requiring authentication
- Cookie storage for faster subsequent checks
- Color-coded results for better readability
- SSL verification control

---

## 🛠 Installation

### 1️⃣ Install Dependencies
```bash
pip install -r requirements.txt

pip install requests selenium colorama tabulate argparse requests

## Arguments
- '-u, --url': Website URL to check
- '-dp, --protected': Enable authentication
- '-d, --disable-ssl': Skip SSL verification
- '--clear-cookies': Clear saved cookies

## Usage

```bash
# Basic check
python HeaderSentry.py -u example.com

# Protected sites
python HeaderSentry.py -u example.com -dp

# Clear saved cookies
python HeaderSentry.py --clear-cookies
```

## Security Note
- `.cookies.pkl` contains sensitive data and is git-ignored
- First visit opens Chrome for authentication
- Subsequent visits use stored cookies