import socket


def dns_lookup(domain):
    try:
        results = socket.getaddrinfo(domain, None)

        ipv4 = []
        ipv6 = []

        for result in results:
            address_family = result[0]
            address = result[4][0]

            if address_family == socket.AF_INET:
                if address not in ipv4:
                    ipv4.append(address)

            elif address_family == socket.AF_INET6:
                if address not in ipv6:
                    ipv6.append(address)

        return {
            "ipv4": ipv4,
            "ipv6": ipv6
        }

    except socket.gaierror:
        return None