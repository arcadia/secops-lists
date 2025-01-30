import os
import requests
import ipaddress
from msal import ConfidentialClientApplication

def main():
    #Set envs
    tenant_id = os.getenv("GRAPH_TENANT_ID")
    client_id = os.getenv("GRAPH_CLIENT_ID")
    client_secret = os.getenv("GRAPH_CLIENT_SECRET")
    named_location_id = "0282fa9f-d415-42f8-b491-9b88f8419ca6"

    # Acquire token
    authority_url = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = ["https://graph.microsoft.com/.default"]
    app = ConfidentialClientApplication(
        client_id=client_id,
        authority=authority_url,
        client_credential=client_secret
    )
    token_result = app.acquire_token_for_client(scopes=scopes)
    access_token = token_result["access_token"]

    #Parse IPs, if not in CIDR format, add "/32". 
    ip_ranges_list = []
    with open("arc-known-threats.txt", "r") as f:
        raw_ips = f.read().splitlines()

    for line in raw_ips:
        line = line.strip()
        if not line:
            continue

        # If the line already has a slash, treat it as CIDR
        if "/" in line:
            try:
                ipaddress.ip_network(line, strict=False)  # Validate
                ip_ranges_list.append(line)  # keep as-is
            except ValueError:
                print(f"Skipping invalid CIDR notation: {line}")
        else:
            # Parse single IP address, then append /32
            try:
                ipaddress.ip_address(line)  # Validate single IP
                ip_ranges_list.append(f"{line}/32")
            except ValueError:
                print(f"Skipping invalid IP address: {line}")

    # Build your request body
    ip_ranges_payload = [
        {
            "@odata.type": "#microsoft.graph.iPv4CidrRange",
            "cidrAddress": cidr
        }
        for cidr in ip_ranges_list
    ]
    request_body = {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "displayName": "Github Blocklist (arc-known-threats.txt)",
        "isTrusted": False,
        "ipRanges": ip_ranges_payload
    }

    # Send PATCH request
    url = f"https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/{named_location_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    response = requests.patch(url, headers=headers, json=request_body)

    if response.status_code == 200:
        print("Named Location updated successfully!")
        print(response.json())
    else:
        print(f"Error updating Named Location: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    main()
