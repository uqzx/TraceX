# TraceX

**OSINT / CSINT tool.**

TraceX is a new and currently **in-development** Python project focused on OSINT, CSINT, reconnaissance, and information gathering.

Right now, TraceX is **only an OSINT tool**. CSINT functionality is planned for later, and when it's added, you'll need to provide **your own authorized private database or data source**. TraceX won't come with a built-in private database.

The project is still pretty small right now and definitely isn't perfect or some massive advanced tool. I'm building it over time, experimenting with different ideas, and adding new modules and features as I learn.

## What it currently has

* DNS lookup for domains, URLs, IPv4, and IPv6 addresses
* A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, DS, DNSKEY, HTTPS, SVCB, TLSA, NAPTR, SSHFP, and DNAME records
* Reverse DNS (PTR), per-address PTR checks, resolver details, query timing, and query counts
* DNSSEC status using DS and DNSKEY evidence
* SPF, DMARC, MTA-STS, and TLS-RPT policy discovery
* Custom DNS resolver support, including multiple comma-separated servers
* Clean Rich terminal tables with clear per-record errors
* Evidence-based username discovery across 77 public services
* Username confidence scoring, response fingerprints, retries, caching, concurrency, and JSON export
* OSINT / information gathering features
* Modular structure
* `rich` terminal interface
* More features coming as the project develops

## Setup

You'll need **Python 3.13+**.

Install the dependencies:

```bash
pip install -r requirements.txt
```

Then run:

```bash
python main.py
```

Choose **DNS Lookup**, enter a domain, URL, or IP address, then optionally enter
DNS servers such as `1.1.1.1,8.8.8.8`. Leave the resolver prompt empty to use
the system resolver configuration.

Choose **Username Lookup** to scan the provider catalog. A `FOUND` result
requires profile evidence, while `LIKELY`, `BLOCKED`, `RATE_LIMITED`, and
`UNKNOWN` remain visibly separate. HTTP 200 alone is never treated as proof.
Results can be exported as JSON for authorized review or automation.

## Contributing

TraceX is still a new project, so **any contributions, ideas, suggestions, bug reports, or improvements are appreciated**.

If you find a bug, have an idea, or want to help improve something, feel free to open an issue or pull request.

You can also find me and get in contact through my website:

**[ruhs.netlify.app](https://ruhs.netlify.app)**

I'm still actively working on TraceX, so things will probably change quite a bit as it grows.

## Disclaimer

TraceX is made for **educational purposes, OSINT/CSINT research, and authorized use**.

Only use it with data, systems, or services you're allowed to access. Don't use it to invade someone's privacy or access information you're not authorized to access.

## Current Status

🚧 **Early development**

TraceX is nowhere near finished yet. It's a small project right now, but the goal is to keep expanding it with more modules, better functionality, and hopefully turn it into something genuinely useful over time.

Thanks for checking it out :)
