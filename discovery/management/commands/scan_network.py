from django.core.management.base import BaseCommand
from discovery.scanner import OTScanner
from discovery.models import DiscoveredDevice

class Command(BaseCommand):
    help = 'Scans a network range and saves results to DB'

    def add_arguments(self, parser):
        parser.add_argument('cidr', type=str, help='CIDR range to scan (e.g. 192.168.0.0/24)')

    def handle(self, *args, **options):
        cidr = options['cidr']
        self.stdout.write(f"Starting scan on {cidr}...")

        scanner = OTScanner()
        results = scanner.scan_network(cidr)

        self.stdout.write(f"Found {len(results)} devices. Saving to database...")

        for device_data in results:
            # update_or_create prevents duplicates
            obj, created = DiscoveredDevice.objects.update_or_create(
                ip_address=device_data['ip'],
                defaults={
                    'hostname': device_data['hostname'],
                    'open_ports': device_data['ports'],
                    'ssl_info': device_data['ssl_info']
                }
            )
            action = "Created" if created else "Updated"
            self.stdout.write(f" - {action}: {device_data['ip']}")

        self.stdout.write(self.style.SUCCESS('Scan Complete!'))
