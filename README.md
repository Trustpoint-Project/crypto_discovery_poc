# crypto_discovery_poc

## Requirements

### Django Application Implementation
- Implement the network discovery functionality as a Django web application.
- Create proper Django models to store discovery results, including IP addresses, hostnames, open ports, and SSL certificate information.
- Ensure the application follows Django best practices for structure and security.
- Display discovery results in a separate view with a table format, showing columns for IP, hostname, ports, SSL status, and certificate details.

### Asynchronous Discovery Trigger
- Add a button in the view to trigger the network discovery process.
- The discovery must run asynchronously (e.g., using Django's background tasks or Celery) to avoid disturbing regular web application processes.
- Provide real-time feedback or status updates on the discovery progress.

### Extended Port Scanning
- Expand the port scanning to include industrial protocol ports commonly used for:
  - OPC UA: Port 4840 (TCP)
  - MQTT: Ports 1883 (TCP, non-secure) and 8883 (TCP, secure over TLS)
- Update the scanner to detect and report these additional ports.
- For SSL-enabled ports (like MQTT over TLS), perform certificate analysis similar to HTTPS.