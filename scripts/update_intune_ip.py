import os
import requests
import ipaddress
from msal import ConfidentialClientApplication

def main():
    tenant_id = os.getenv("GRAPH_TENANT_ID")
    client_id = os.getenv("GRAPH_CLIENT_ID")
    client_secret = os.getenv("GRAPH_CLIENT_SECRET")

    # Replace with your Named Location ID from Intune
    named_location_id = "0282fa9f-d415-42f8-b491-9b88f8419ca6"

    if not all([tenant_id, client_id, client_secret, named_location_id]):
        raise ValueError("Missing required environment variables.")

    # Acquire a token from Azure AD (MSAL Client-Credentials flow)
    authority_url = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = ["https://graph.microsoft.com/.default"]
    app = ConfidentialClientApplication(
        client_id=client_id,
        authority=authority_url,
        client_credential=client_secret
    )
    token_result = app.acquire_token_for_client(scopes=scopes)
    if "access_token" not in token_result:
        raise Exception(f"Token error: {token_result.get('error_description')}")

    access_token = token_result["access_token"]

    # Read IPs from the text file and append /32 to each
    ip_ranges_list = []
    try:
        with open("secops-lists/arc-known-threats.txt", "r") as f:
            raw_ips = f.read().splitlines()
        
        for line in raw_ips:
            line = line.strip()
            if line:
                # Optional: Validate IP correctness
                ipaddress.ip_address(line)  # raises ValueError if invalid
                ip_ranges_list.append(f"{line}/32")

    except FileNotFoundError:
        raise FileNotFoundError("File secops-lists/arc-known-threats.txt not found in the repo.")
    except ValueError as e:
        raise ValueError(f"Invalid IP address in the list: {e}")

    # Build the PATCH payload
    # For each IP string, create a dict with @odata.type and cidrAddress
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

    # Send the PATCH request to update the Named Location
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
