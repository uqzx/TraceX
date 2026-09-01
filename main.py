import os
import requests
import time
from modules.dns import dns_lookup

from rich import print


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
        domain = input("Domain: ").strip()

        if not domain:
            print("[red]Domain cannot be empty.[/red]")

        elif " " in domain:
            print("[red]Domain cannot contain spaces.[/red]")

        elif "." not in domain:
            print("[red]Invalid domain.[/red]")

        else:
            result = dns_lookup(domain)

            if result is None:
                print("[red]Could not resolve that domain.[/red]")

            else:
                print()
                print("[bright_white]DNS Lookup[/bright_white]")
                print(f"[grey70]Domain:[/grey70] {domain}")

                print("[grey70]IPv4:[/grey70]")
                for ip in result["ipv4"]:
                    print(f"  {ip}")

                print("[grey70]IPv6:[/grey70]")
                for ip in result["ipv6"]:
                    print(f"  {ip}")

    elif choice == "2":
        print("[grey70]Username Lookup selected.[/grey70]")

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