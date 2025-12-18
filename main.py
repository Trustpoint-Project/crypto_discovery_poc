from discovery_module.core import OTScanner
import json

def main():
    # Scan your local machine (127.0.0.1) just to test the code runs
    target_cidr = "10.100.13.0/24"

    scanner = OTScanner(timeout=0.5, max_workers=5)
    results = scanner.scan_network(target_cidr)

    print("\n--- Final Results ---")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()