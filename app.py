from src.probes.probe_library import get_all_probes

def main():
    print("Ghosttwatch system booted")
 
    probes = get_all_probes()

    print("\nLoaded probe categories:\n")

    for category, payloads in probes.items():
        print(f"- {category}: {len(payloads)} probes")

    total = sum(len(p) for p in probes.values())
    print(f"\nTotal probes loaded: {total}")


if __name__ == "__main__":
    main()
