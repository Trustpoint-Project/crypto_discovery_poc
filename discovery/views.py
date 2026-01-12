import threading
import csv
from django.db.models import Q  # <--- NEW IMPORT
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponse
from .models import DiscoveredDevice
from .scanner import OTScanner

SCAN_RUNNING = False

def run_scan_in_background(cidr):
    global SCAN_RUNNING
    SCAN_RUNNING = True
    print(f"--- Background Scan Started on {cidr} ---")
    try:
        scanner = OTScanner()
        results = scanner.scan_network(cidr)
        for device_data in results:
            DiscoveredDevice.objects.update_or_create(
                ip_address=device_data['ip'],
                defaults={
                    'hostname': device_data['hostname'],
                    'open_ports': device_data['ports'],
                    'ssl_info': device_data['ssl_info']
                }
            )
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("--- Background Scan Finished ---")
        SCAN_RUNNING = False

def device_list(request):
    """Show the dashboard with stats and search."""
    # Start with all devices
    devices = DiscoveredDevice.objects.all().order_by('-last_seen')

    # --- SEARCH LOGIC ---
    query = request.GET.get('q')
    if query:
        # Filter by IP OR Hostname
        devices = devices.filter(
            Q(ip_address__icontains=query) | 
            Q(hostname__icontains=query)
        )

    # --- STATS LOGIC (Always calculate based on ALL devices, not just search results) ---
    all_devices = DiscoveredDevice.objects.all()
    stats = {
        'total': all_devices.count(),
        'risks': 0,
        'industrial': 0
    }
    
    ot_ports = [502, 102, 44818, 4840, 1883, 8883]

    for d in all_devices:
        if d.ssl_info and d.ssl_info.get('is_self_signed'):
            stats['risks'] += 1
        if any(port in ot_ports for port in d.open_ports):
            stats['industrial'] += 1

    context = {
        'devices': devices,
        'scan_running': SCAN_RUNNING,
        'stats': stats,
        'search_query': query  # Pass back to template so box stays filled
    }
    return render(request, 'discovery/device_list.html', context)

def device_detail(request, device_id):
    device = get_object_or_404(DiscoveredDevice, id=device_id)
    return render(request, 'discovery/device_detail.html', {'device': device})

def start_scan(request):
    global SCAN_RUNNING
    if request.method == 'POST':
        target_cidr = request.POST.get('cidr')
        if not target_cidr:
            messages.error(request, "Please enter a valid CIDR range.")
            return redirect('device_list')

        if not SCAN_RUNNING:
            thread = threading.Thread(target=run_scan_in_background, args=(target_cidr,))
            thread.daemon = True
            thread.start()
            messages.success(request, f"Scan started on {target_cidr}. Please wait...")
        else:
            messages.warning(request, "A scan is already in progress.")
    return redirect('device_list')

def export_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="trustpoint_inventory.csv"'
    writer = csv.writer(response)
    writer.writerow(['IP Address', 'Hostname', 'Open Ports', 'SSL Status', 'Issuer', 'Last Seen'])
    for device in DiscoveredDevice.objects.all().order_by('ip_address'):
        ssl_status = "N/A"
        issuer = ""
        if device.ssl_info:
            if device.ssl_info.get('is_self_signed'):
                ssl_status = "Self-Signed"
            else:
                ssl_status = "Valid CA"
            issuer = device.ssl_info.get('issuer', '')
        writer.writerow([
            device.ip_address, device.hostname, device.open_ports, ssl_status, issuer, device.last_seen
        ])
    return response
