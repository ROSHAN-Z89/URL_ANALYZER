from urllib.parse import urlparse

def count_subdomains(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    if hostname is None:
        return 0

    parts = hostname.split('.')

    # Return subdomain count (e.g., a.b.example.com => ['a', 'b', 'example', 'com'] => 2 subdomains)
    if len(parts) <= 2:
        return 0
    return len(parts) - 2
