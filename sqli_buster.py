import argparse
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None

    method = form.attrs.get("method", "get").lower()

    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def scan_sql_injection(args):
    url = args.url

    for c in "\"'":
        new_url = f"{url}{c}"
        print(Fore.YELLOW + "[!] Trying", new_url)
        res = s.get(new_url)
        if is_vulnerable(res):
            print(Fore.GREEN + "[+] SQL Injection vulnerability detected, link:", new_url)
            return

    forms = get_all_forms(url)
    print(Fore.CYAN + f"[+] Detected {len(forms)} forms on {url}.")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for form in forms:
            form_details = get_form_details(form)
            futures.append(executor.submit(test_form, url, form_details, args))

        for future in futures:
            if future.result():
                print(Fore.GREEN + "[+] SQL Injection scan completed. Vulnerability found.")
                return

    print(Fore.CYAN + "[+] SQL Injection scan completed. No vulnerabilities found.")

def test_form(url, form_details, args):
    for c in "\"'":
        data = {}
        for input_tag in form_details["inputs"]:
            if input_tag["value"] or input_tag["type"] == "hidden":
                try:
                    data[input_tag["name"]] = input_tag["value"] + c
                except:
                    pass
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = f"test{c}"

        form_url = urljoin(url, form_details["action"])
        if form_details["method"] == "post":
            res = s.post(form_url, data=data)
        elif form_details["method"] == "get":
            res = s.get(form_url, params=data)

        if is_vulnerable(res):
            print(Fore.GREEN + "[+] SQL Injection vulnerability detected, link:", form_url)
            print(Fore.GREEN + "[+] Form:")
            pprint(form_details)
            return True

    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan for SQL Injection vulnerabilities.')
    parser.add_argument('-u', '--url', type=str, required=True, help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads for concurrent scanning')
    args = parser.parse_args()

    scan_sql_injection(args)
