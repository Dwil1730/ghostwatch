def run_probe(self, probe: dict):

    payloads = probe.get("payload", [])

    results = []

    for payload in payloads:

        result = self.client.send(payload)

        response_text = result.get("response", "")
        latency = result.get("latency_ms", 0)

        intelligence = self.intel.analyze(response_text, payload)

        results.append({
            "probe_name": probe.get("name"),
            "attack_type": probe.get("attack_type"),
            "mitre_id": probe.get("mitre_id"),
            "owasp_category": probe.get("owasp_category"),

            "payload": payload,
            "response": response_text,
            "latency_ms": latency,

            "risk_score": intelligence["risk_score"],
            "verdict": intelligence["verdict"],
            "signals": intelligence["signals"],
        })

    return results
