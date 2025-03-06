import requests
from colorama import Fore, Style,Back, init
from tabulate import tabulate
from selenium import webdriver
import textwrap
import argparse

redirect_attempts = 0
max_redirects = 5
active_headers =0
session = requests.Session()

# argument parser
parser = argparse.ArgumentParser(description="Security Headers Checker")

parser.add_argument(
    "-URL",
    action="store",
    dest="url",
    required=True,
    help="The website URL to check (e.g., example.com).",
)

parser.add_argument(
    "-IAP",
    action="store_true",  # Boolean flag (True/False)
    help="Enable authentication for IAP-protected websites.",
)


# List of common security headers -
security_headers = [
    "Content-Security-Policy",  # CSP
    "Content-Security-Policy-Report-Only",  # CSP Report only
    "Strict-Transport-Security",  # HSTS
    "X-Frame-Options",  # Clickjacking protection
    "X-Content-Type-Options",  # MIME sniffing protection
    "Referrer-Policy",  # Referrer policy
    "Permissions-Policy",  # Feature policy (formerly Feature-Policy)
    "Cache-Control",  # Cache control policy
    "Cross-Origin-Opener-Policy",  # COOP
    "Cross-Origin-Resource-Policy",  # CORP
    "X-Permitted-Cross-Domain-Policies",  # Cross domain policies
    "X-Download-Options",  # Prevent file opening in IE
    "X-DNS-Prefetch-Control",  # DNS prefetch control
    "Access-Control-Allow-Headers",  # Allowed Headers for CORS
    "Access-Control-Allow-Origin",  # CORS
    "Clear-Site-Data",  # Clear data
    "Pragma",  # Cache control for HTTP/1.0
    "Surrogate-Control",  # Cache control for reverse proxies/CDNs
    "X-XSS-Protection",  # XSS protection
    "Expect-CT",  # Certificate Transparency
    "CF-Cache-Status",  # Cloudflare cache status
    "CF-RAY",  # Cloudflare Ray ID
    "xf-custom_header", #any custom header needed
]


def get_session():
    if args.IAP:
        print(f"{Fore.YELLOW}Launching browser for IAP authentication...{Style.RESET_ALL}")
        try:
            browser = webdriver.Chrome()
            browser.get(url)
            input("Press Enter after logging in and wait for redirection to complete")
            cookies = browser.get_cookies()
            for cookie in cookies:
                session.cookies.set(cookie["name"], cookie["value"])
            browser.quit()
        except Exception as e:
            print(f"{Fore.RED}Error with WebDriver: {e}{Style.RESET_ALL}")
            exit(1)
    else:
        print(f"{Fore.YELLOW}No authentication enabled{Style.RESET_ALL}")
    return session


def check_security_headers(url, session):
    redirect_attempts = 0
    # Send a request to the URL
    try:
        response = session.get(url,timeout=10)
        print("Args URL: ", url)
        print(
            f"{Fore.BLUE}Final URL: {response.url} - {response.status_code}{Style.RESET_ALL}"
        )
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return
    while (
        args.IAP
        and response.url.rstrip("/") != url
        and redirect_attempts < max_redirects
    ):
        input(f"{Fore.RED}Wait for redirection to complete{Style.RESET_ALL}")
        redirect_attempts += 1
    if redirect_attempts >= max_redirects:
        print(
            f"{Fore.RED}Too many redirects! Something might be wrong.{Style.RESET_ALL}"
        )
        return
    else:
        print(f"{Fore.GREEN}Redirection completed{Style.RESET_ALL}")
        # Get the response headers
        headers = response.headers
        results = []
        value = ""
        # Check and display security headers

        for header in security_headers:
            global active_headers
            active_headers = 0
             # Number of active headers
            if header in headers:
             
                result = f"{Fore.GREEN}Present{Style.RESET_ALL}"
                value = headers[header]
                active_headers +=1
                if len(value) > 80:
                    value = '\n'.join(textwrap.wrap(value, width=80))
            else:
                result = f"{Fore.RED}Not present{Style.RESET_ALL}"
                value = "N/A"
            results.append([header, result, value])

        print(f"Checking security headers for {url}:\n")

        formatted_results = []
        for i, row in enumerate(results):
            formatted_results.append(row)
            if i == 9:
                formatted_results.append([Back.GREEN + "---", "---", " "*60+Style.RESET_ALL]) 
               
        print(tabulate(formatted_results, headers=["Header", "Status", "Value"], tablefmt="grid"))
        print(f"{Fore.MAGENTA}========{active_headers} / {len(security_headers)} enabled headers========{Style.RESET_ALL}")


if __name__ == "__main__":
    args = parser.parse_args()
    if args.url.startswith("http://") or args.url.startswith("https://"):
        url = args.url
    else:
        url = f"https://{args.url}"

    check_security_headers(url, get_session())
