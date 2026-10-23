MITRE_TECHNIQUES = {
    "SSH_BRUTE_FORCE": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },

    "SSH_FAILURES_THEN_SUCCESS": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    }
}


def get_mitre_mapping(alert_type):
    return MITRE_TECHNIQUES.get(
        alert_type,
        {
            "id": "UNKNOWN",
            "name": "Unknown Technique",
            "tactic": "Unknown"
        }
    )
