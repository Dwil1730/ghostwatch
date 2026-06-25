class BaseProbe:
    attack_type = "base"
    mitre_id = "UNKNOWN"
    owasp_category = "UNKNOWN"
    submittable = True
    description = ""

    def payloads(self):
        raise NotImplementedError("Probe must implement payloads()")
