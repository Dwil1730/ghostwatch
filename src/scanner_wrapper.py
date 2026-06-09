from src.probes.probe_library import ProbeLibrary


class ScannerWrapper:
    def __init__(self):
        self.probe_lib = ProbeLibrary()

    def run_probe(self, target_url, probe_type):
        return self.probe_lib.run_probe(target_url, probe_type)

    def run_all_probes(self, target_url):
        return self.probe_lib.run_all_probes(target_url)
