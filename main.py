import os
import time
from modules.dns import dns_lookup, normalize_target
from modules.username import ResultStatus, report_json, scan_username

from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


ascii_art = """
          ▄▄▄█████▓ ██▀███   ▄▄▄       ▄████▄  ▓█████ ▒██   ██▒
          ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▒██▀ ▀█  ▓█   ▀ ▒▒ █ █ ▒░
          ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▒███   ░░  █   ░
          ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▒▓█  ▄  ░ █ █ ▒ 
            ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░░▒████▒▒██▒ ▒██▒
            ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░░░ ▒░ ░▒▒ ░ ░▓ ░
            ░      ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒    ░ ░  ░░░   ░▒ ░
           ░        ░░   ░   ░   ▒   ░           ░    ░    ░  
                     ░           ░  ░░ ░         ░  ░ ░    ░  
"""

console = Console()


def show_username_result(report):
    """Render only evidence-backed findings prominently, then summarize all checks."""
    if report.invalid_reason:
        console.print(f"[red]{report.invalid_reason}[/red]")
        return

    summary = report.counts
    summary_text = (
        f"[grey70]Username[/grey70] {report.normalized}\n"
        f"[grey70]Providers[/grey70] {len(report.results)}\n"
        f"[grey70]Found[/grey70] {summary['FOUND']}  "
        f"[grey70]Likely[/grey70] {summary['LIKELY']}  "
        f"[grey70]Not found[/grey70] {summary['NOT_FOUND']}\n"
        f"[grey70]Blocked[/grey70] {summary['BLOCKED']}  "
        f"[grey70]Limited[/grey70] {summary['RATE_LIMITED']}  "
        f"[grey70]Errors[/grey70] {summary['ERROR']}\n"
        f"[grey70]Elapsed[/grey70] {report.elapsed_ms} ms"
    )
    console.print(Panel(summary_text, title="Username Investigation", border_style="cyan"))

    findings = Table(show_header=True, header_style="bold bright_white", box=None, pad_edge=False)
    findings.add_column("Service", style="cyan", no_wrap=True)
    findings.add_column("Category", style="grey70")
    findings.add_column("Confidence", justify="right")
    findings.add_column("Evidence", style="white")
    for result in report.results:
        if result.status not in {ResultStatus.FOUND, ResultStatus.LIKELY}:
            continue
        evidence = " | ".join(result.evidence) if result.evidence else result.error or "limited evidence"
        findings.add_row(result.provider, result.category, f"{result.confidence}%", Text(evidence))
    if findings.row_count:
        console.print(Panel(findings, title="Evidence-backed Profiles", border_style="green"))
    else:
        console.print(Panel("No profile was confirmed by the available evidence.", title="Findings", border_style="yellow"))

    uncertain = Table(show_header=True, header_style="bold bright_white", box=None, pad_edge=False)
    uncertain.add_column("Service", style="cyan")
    uncertain.add_column("Status")
    uncertain.add_column("Detail", style="white")
    for result in report.results:
        if result.status in {ResultStatus.FOUND, ResultStatus.LIKELY, ResultStatus.NOT_FOUND}:
            continue
        detail = result.error or "; ".join(result.evidence) or "no additional detail"
        uncertain.add_row(result.provider, result.status.value, Text(detail))
    if uncertain.row_count:
        console.print(Panel(uncertain, title="Uncertain or Unavailable Checks", border_style="yellow"))


def show_dns_result(result):
    records = result["records"]
    table = Table(show_header=True, header_style="bold bright_white", box=None, pad_edge=False)
    table.add_column("Record", style="cyan", width=8)
    table.add_column("Value", style="white")

    record_order = (
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "DS",
        "DNSKEY", "TLSA", "HTTPS", "SVCB", "NAPTR", "SSHFP", "DNAME", "PTR",
    )
    for record_type in record_order:
        for value in records.get(record_type, []):
            table.add_row(record_type, Text(value))

    reverse_records = records.get("reverse", {})
    for address, names in reverse_records.items():
        reverse_text = f"{address} -> {', '.join(names) if names else 'no record'}"
        table.add_row("PTR", Text(reverse_text))

    if not table.row_count:
        table.add_row("-", "No DNS records were returned.")

    summary = (
        f"[grey70]Target[/grey70]  {result['domain']}\n"
        f"[grey70]Resolver[/grey70] {', '.join(result['resolver'])}\n"
        f"[grey70]Time[/grey70]     {result['elapsed_ms']} ms\n"
        f"[grey70]Queries[/grey70]  {result['query_count']}"
    )
    console.print(Panel(summary, title="DNS Lookup", border_style="cyan"))
    console.print(table)

    security = result["dnssec"]
    console.print(
        Panel(
            f"[grey70]DNSSEC[/grey70] {security['status']}  "
            f"(DS: {security['ds_records']}, DNSKEY: {security['dnskey_records']})",
            title="Security",
            border_style="green" if security["status"] == "signed" else "yellow",
        )
    )

    if result["policies"]:
        policy_table = Table(show_header=True, header_style="bold bright_white", box=None)
        policy_table.add_column("Policy", style="cyan")
        policy_table.add_column("TXT value", style="white")
        for policy_name, values in result["policies"].items():
            for value in values:
                policy_table.add_row(policy_name, Text(value))
        console.print(Panel(policy_table, title="Email Security Policies", border_style="blue"))

    if result["errors"]:
        errors = "\n".join(
            f"[yellow]{record_type}[/yellow]: {message}"
            for record_type, message in result["errors"].items()
        )
        console.print(Panel(errors, title="Unanswered Queries", border_style="yellow"))

while True:
    os.system("cls" if os.name == "nt" else "clear")

    try:
        width = os.get_terminal_size().columns
    except OSError:
        width = 80

    for line in ascii_art.splitlines():
        print(f"[bright_white]{line.center(width)}[/bright_white]")

    print()
    print(f"[grey70]{'For issues or recommendations, my Discord and other socials'.center(width)}[/grey70]")
    print(f"[white]{'can be found at: https://ruhs.netlify.app'.center(width)}[/white]")
    print(f"[grey50]{'version 0.3'.center(width)}[/grey50]")
    print()

    print("[white]1.[/white] DNS Lookup")
    print("[white]2.[/white] Username Lookup")
    print("[white]3.[/white] Email Lookup")
    print("[white]4.[/white] Phone Number Lookup")
    print("[white]5.[/white] Port Scan")
    print("[white]6.[/white] Exit")
    print()

    choice = input("> ")

    if choice == "1":
        domain = input("Domain, URL, or IP: ").strip()

        try:
            normalize_target(domain)
        except ValueError as error:
            print(f"[red]{error}[/red]")
        else:
            resolver_input = input("DNS server(s) [Enter for system default]: ").strip()
            nameservers = tuple(
                item.strip() for item in resolver_input.split(",") if item.strip()
            ) or None
            result = dns_lookup(domain, nameservers=nameservers)
            if result is None or not result["has_answers"]:
                print("[red]No DNS answers were found. Check the target and try again.[/red]")
            else:
                print()
                show_dns_result(result)

    elif choice == "2":
        username = input("Username: ").strip()
        workers_input = input("Parallel checks [8]: ").strip()
        try:
            workers = max(1, min(int(workers_input or "8"), 16))
        except ValueError:
            print("[red]Parallel checks must be a number.[/red]")
        else:
            report = scan_username(username, workers=workers)
            print()
            show_username_result(report)
            export_path = input("JSON export path [Enter to skip]: ").strip()
            if export_path:
                try:
                    with open(export_path, "w", encoding="utf-8") as export_file:
                        export_file.write(report_json(report))
                    print(f"[green]Report exported to {export_path}[/green]")
                except OSError as error:
                    print(f"[red]Could not export report: {error}[/red]")

    elif choice == "3":
        print("[grey70]Email Lookup selected.[/grey70]")

    elif choice == "4":
        print("[grey70]Phone Number Lookup selected.[/grey70]")

    elif choice == "5":
        print("[grey70]Port scan selected.[/grey70]")

    elif choice == "6":
        print("[grey70]Exiting...[/grey70]")
        break

    else:
        print("[red]Invalid choice.[/red]")
        time.sleep(1)
        continue

    input("Press Enter to continue...")