"""
MITRE ATT&CK Mapping Module

Maps common attacks to their corresponding
MITRE ATT&CK information.
"""

mitre_attack_map = {

    "Port Scan": {
        "tactic": "Reconnaissance",
        "technique": "Active Scanning",
        "technique_id": "T1595",
        "description": (
            "The attacker actively scans systems or networks to discover "
            "open ports, services, operating systems, or vulnerabilities "
            "before launching an attack."
        ),
        "mitigation": (
            "Use firewalls, Intrusion Detection Systems (IDS), "
            "Intrusion Prevention Systems (IPS), disable unused ports, "
            "and monitor for unusual scanning activity."
        )
    },

    "DDoS": {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "technique_id": "T1498",
        "description": (
            "The attacker floods the victim's network or services with "
            "large volumes of traffic to make them unavailable."
        ),
        "mitigation": (
            "Deploy DDoS protection, rate limiting, traffic filtering, "
            "load balancing, and cloud-based mitigation services."
        )
    },

    "Brute Force": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "description": (
            "The attacker repeatedly attempts different username and "
            "password combinations until the correct credentials are found."
        ),
        "mitigation": (
            "Enable Multi-Factor Authentication (MFA), enforce strong "
            "password policies, implement account lockout mechanisms, "
            "and monitor failed login attempts."
        )
    },

    "Web Attack": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "description": (
            "The attacker exploits vulnerabilities in public-facing web "
            "applications to gain unauthorized access."
        ),
        "mitigation": (
            "Keep applications updated, use a Web Application Firewall "
            "(WAF), validate all user input, and perform regular "
            "vulnerability assessments."
        )
    },

    "Bot": {
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
        "description": (
            "A compromised host communicates with a remote command-and-control "
            "(C2) server using standard application layer protocols."
        ),
        "mitigation": (
            "Monitor outbound network traffic, block known malicious "
            "domains/IPs, deploy Endpoint Detection and Response (EDR), "
            "and segment networks."
        )
    }

}


def get_attack_details(attack_name):
    """
    Returns MITRE ATT&CK information for a given attack.

    Parameters
    ----------
    attack_name : str
        Name of the attack.

    Returns
    -------
    dict or None
        MITRE mapping information.
    """

    return mitre_attack_map.get(attack_name)


def get_all_attacks():
    """
    Returns a list of all supported attack names.
    """

    return list(mitre_attack_map.keys())