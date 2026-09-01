import requests

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive"
}


def github_username_lookup(username):
    github_url = f"https://github.com/{username}"

    try:
        response = requests.get(
            github_url,
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            return "FOUND"

        elif response.status_code == 404:
            return "NOT_FOUND"

        elif response.status_code == 403:
            return "BLOCKED"

        elif response.status_code == 429:
            return "RATE_LIMITED"

        elif response.status_code >= 500:
            return "ERROR"

        else:
            return "UNKNOWN"

    except requests.RequestException:
        return "ERROR"