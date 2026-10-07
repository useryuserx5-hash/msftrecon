#!/usr/bin/env python3

"""
Simplified Microsoft 365 Tenant and Service Detection Tool.
Checks if a domain uses Microsoft 365 and retrieves tenant information.
"""

import argparse
import dns.resolver
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
import json
import socket
from typing import Dict, List, Optional, Any
from urllib.error import HTTPError, URLError


class M365Checker:
    def __init__(self, domain: str, timeout: int = 10, debug: bool = False):
        self.domain = domain
        self.timeout = timeout
        self.debug = debug
        self.domain_prefix = domain.split('.')[0]

        self.tenant_name = ""
        self.domains = []

        self.autodiscover = "autodiscover-s.outlook.com"
        self.ms_login = "login.microsoftonline.com"

    def get_federation_info(self) -> Optional[Dict]:
        """Get Federation information for the domain."""
        try:
            url = f"https://{self.ms_login}/getuserrealm.srf?login=user@{self.domain}&json=1"
            request = Request(url, headers={"User-agent": "Mozilla/5.0"})
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            if self.debug:
                print(f"DEBUG: Federation info error: {e}")
            return None

    def get_mx_records(self) -> List[str]:
        """Get MX records for the domain."""
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            return [str(x.exchange).rstrip('.') for x in mx_records]
        except Exception:
            return []

    def get_txt_records(self) -> List[str]:
        """Get TXT records for the domain."""
        try:
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
            return [str(x).strip('"') for x in txt_records]
        except Exception:
            return []

    def get_autodiscover_endpoint(self) -> Optional[str]:
        """Check Autodiscover CNAME."""
        try:
            autodiscover = f"autodiscover.{self.domain}"
            return socket.gethostbyname(autodiscover)
        except Exception:
            return None

    def get_tenant_id(self) -> Optional[str]:
        """Get tenant ID from OpenID configuration."""
        try:
            url = f"https://{self.ms_login}/{self.domain}/v2.0/.well-known/openid-configuration"
            request = Request(url, headers={"User-agent": "Mozilla/5.0"})
            with urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode())
                token_endpoint = data.get("token_endpoint", "")
                tenant_id = token_endpoint.split("/")[3] if token_endpoint else None
                return tenant_id if tenant_id and tenant_id != "v2.0" else None
        except Exception:
            return None

    def get_domains(self, domain: str) -> None:
        """Enumerate all domains associated with the tenant via Autodiscover."""
        body = f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" 
            xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" 
            xmlns:a="http://www.w3.org/2005/08/addressing" 
            xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
            <soap:Header>
                <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
                <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
                <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
                <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
                <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
                </a:ReplyTo>
            </soap:Header>
            <soap:Body>
                <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Request>
                    <Domain>{domain}</Domain>
                </Request>
                </GetFederationInformationRequestMessage>
            </soap:Body>
        </soap:Envelope>"""

        headers = {
            "Content-type": "text/xml; charset=utf-8",
            "User-agent": "AutodiscoverClient"
        }

        url = f"https://{self.autodiscover}/autodiscover/autodiscover.svc"

        try:
            httprequest = Request(url, headers=headers, data=body.encode())
            with urlopen(httprequest, timeout=self.timeout) as response:
                response_text = response.read().decode()
        except Exception as e:
            if self.debug:
                print(f"DEBUG: Domain enumeration error: {e}")
            self.domains = []
            self.tenant_name = ""
            return

        self.domains = []
        try:
            tree = ET.fromstring(response_text)
            for elem in tree.iter():
                if elem.tag == "{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domain":
                    self.domains.append(elem.text)
        except Exception as e:
            if self.debug:
                print(f"DEBUG: XML parse error: {e}")

        # Extract tenant name from onmicrosoft.com domain
        self.tenant_name = ""
        for d in self.domains:
            if "onmicrosoft.com" in d or "partner.onmschina.cn" in d or "onmicrosoft.us" in d:
                self.tenant_name = d.split(".")[0]

    def check_m365_detection(self, include_tenant_info: bool = False) -> Dict[str, Any]:
        """Check if domain uses Microsoft 365 and retrieve tenant info."""
        results = {
            "domain": self.domain,
            "uses_microsoft_365": False,
            "confidence": "low",
            "indicators": {
                "mx_records": [],
                "txt_records": [],
                "autodiscover": None,
                "federation": {}
            }
        }

        # Include tenant info if requested
        if include_tenant_info:
            results["tenant_info"] = {
                "tenant_name": "",
                "tenant_id": "",
                "domains": []
            }
            self.get_domains(self.domain)
            results["tenant_info"]["tenant_name"] = self.tenant_name
            results["tenant_info"]["tenant_id"] = self.get_tenant_id()
            results["tenant_info"]["domains"] = self.domains

        # 1. Check MX Records
        mx_records = self.get_mx_records()
        results["indicators"]["mx_records"] = mx_records

        # 2. Check TXT Records
        txt_records = self.get_txt_records()
        results["indicators"]["txt_records"] = txt_records

        # 3. Check Autodiscover
        autodiscover = self.get_autodiscover_endpoint()
        results["indicators"]["autodiscover"] = autodiscover

        # 4. Check Federation Info
        fed_info = self.get_federation_info()
        if fed_info:
            results["indicators"]["federation"] = {
                "name_space_type": fed_info.get("NameSpaceType", "Unknown"),
                "domain_type": fed_info.get("DomainType", "Unknown"),
                "cloud_instance": fed_info.get("CloudInstanceName", "Unknown")
            }

        # Determine if using Microsoft 365
        m365_indicators = []

        if any("outlook.com" in mx.lower() for mx in mx_records):
            m365_indicators.append("MX records point to Outlook.com (Exchange Online)")
        if any("protection.outlook.com" in mx.lower() for mx in mx_records):
            m365_indicators.append("MX records point to Outlook protection (Exchange Online)")
        if any("spf.protection.outlook.com" in txt.lower() for txt in txt_records):
            m365_indicators.append("SPF includes Outlook.com protection")
        if any("ms=" in txt.lower() and any(c.isdigit() for c in txt) for txt in txt_records):
            m365_indicators.append("Domain verification record found")
        if fed_info:
            cloud_instance = fed_info.get("CloudInstanceName", "")
            if "microsoftonline" in cloud_instance.lower():
                m365_indicators.append(f"Cloud instance: {cloud_instance}")

        # Determine confidence level
        indicator_count = len(m365_indicators)
        if indicator_count >= 3:
            results["uses_microsoft_365"] = True
            results["confidence"] = "high"
        elif indicator_count >= 2:
            results["uses_microsoft_365"] = True
            results["confidence"] = "medium"
        elif indicator_count >= 1:
            results["uses_microsoft_365"] = True
            results["confidence"] = "low"
        else:
            results["uses_microsoft_365"] = False
            results["confidence"] = "none"

        return results


def main():
    parser = argparse.ArgumentParser(
        description="Check if a domain uses Microsoft 365 and retrieve tenant information.",
        epilog="Example: python m365check.py -d example.com"
    )

    parser.add_argument("-d", "--domain", required=True,
                        help="Input domain name (e.g., example.com)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout for HTTP requests in seconds (default: 10)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose error output")

    args = parser.parse_args()

    checker = M365Checker(args.domain, timeout=args.timeout, debug=args.debug)

    # Always include tenant info in the output
    results = checker.check_m365_detection(include_tenant_info=True)

    # Always output JSON
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
