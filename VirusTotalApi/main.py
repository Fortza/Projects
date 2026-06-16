import ipaddress
import validators

from virustotal import (
    get_ip_report,
    get_domain_report,
    parse_report
)


# Leser targets fra fil
def read_targets(filename):
    with open(filename) as f:

        lines = f.readlines()
        
        return [
            line.strip()
            for line in lines[3:]
            if line.strip()
        ]


# Sjekker om input er IP-adresse
def is_ip(target):

    try:
        ipaddress.ip_address(target)
        return True

    except ValueError:
        return False


# Sjekker om input er domenenavn
def is_domain(target):

    return validators.domain(target)


# Leser targets
targets = read_targets("targets.txt")

# Lister for validering
valid_targets = []
invalid_targets = []


# Validerer alle targets
for target in targets:

    if is_ip(target):
        valid_targets.append(target)

    elif is_domain(target):
        valid_targets.append(target)

    else:
        invalid_targets.append(target)


print(f"Valid targets: {len(valid_targets)}")
print(f"Invalid targets: {len(invalid_targets)}")


# VirusTotal test
for target in valid_targets:

    if is_ip(target):
        result = get_ip_report(target)

    else:
        result = get_domain_report(target)

    report = parse_report(result)

    print(f"\nTarget: {target}")
    print(f"Malicious: {report['malicious']}")
    print(f"Suspicious: {report['suspicious']}")
    print(f"Harmless: {report['harmless']}")
    print(f"Undetected: {report['undetected']}")

    break