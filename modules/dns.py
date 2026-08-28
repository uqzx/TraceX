import socket
from rich import print

# temporarily clears the terminal for testing
import os
os.system("cls")

while True:
    domain = input("Domain: ")

    if not domain:
        print("[red]Domain cannot be empty.[/red]")
        continue

    elif " " in domain:
        print("[red]Domain cannot contain spaces.[/red]")
        continue

    elif "." not in domain:
        print("[red]Invalid domain, try again.[/red]")
        continue

    elif domain.startswith("."):
        print("[red]Invalid domain, try again.[/red]")
        continue

    elif domain.endswith("."):
        print("[red]Invalid domain, try again.[/red]")
        continue

    break

try:
    ip = socket.gethostbyname(domain)
    print(f"Domain: {domain}")
    print(f"IP: {ip}")

except socket.gaierror:
    print("[red]Could not resolve that domain.[/red]")