import sys
from typing import Optional, Dict, List, Tuple
from bs4 import BeautifulSoup as bs
import requests
from prettytable import PrettyTable
import apt_pkg
import os
import re
from dataclasses import dataclass
from datetime import datetime


# GPT out
@dataclass
class Vulnerability:
    """Class to store vulnerability information"""
    bug_id: str
    package: str
    version: str
    urgency: str
    remote: bool
    fix_available: bool
    description: str

class SecurityAnalyzer:
    def __init__(self):
        # Initialize apt_pkg
        apt_pkg.init()
        # Use version_compare directly
        self.version_compare = apt_pkg.version_compare
        
    def check_installed_packages(self, status_file: str = "/var/lib/dpkg/status") -> List[Dict]:
        """
        Read and analyze installed packages from dpkg status file
        """
        installed_packages = []
        
        try:
            with open(status_file, 'r') as f:
                package_data = {}
                for line in f:
                    if line.strip() == "":
                        if package_data.get('Status', '').find('installed') != -1:
                            installed_packages.append(package_data)
                        package_data = {}
                    else:
                        key_value = line.split(':', 1)
                        if len(key_value) == 2:
                            package_data[key_value[0].strip()] = key_value[1].strip()
                            
            return installed_packages
        except Exception as e:
            print(f"Error reading status file: {e}")
            return []

    def analyze_package_versions(self, packages: List[Dict]) -> PrettyTable:
        """
        Analyze package versions and create a formatted table
        """
        table = PrettyTable()
        table.field_names = ["Package", "Version", "Source Package", "Status"]
        table.align = "l"
        
        for pkg in packages:
            if 'Package' in pkg and 'Version' in pkg:
                source = pkg.get('Source', pkg['Package'])
                if ' ' in source:
                    source = source.split(' ')[0]
                    
                table.add_row([
                    pkg['Package'],
                    pkg['Version'],
                    source,
                    self.check_version_status(pkg['Version'])
                ])
                
        return table

    def check_version_status(self, version: str) -> str:
        """
        Check if a package version might need updating
        """
        try:
            if not re.match(r'^[\w\-+.~]+$', version):
                return "Invalid Version"
            return "OK"
        except Exception:
            return "Version Check Failed"

    def check_package_vulnerabilities(self, package: str) -> List[Vulnerability]:
        """
        Check specific package for known vulnerabilities
        """
        vulnerabilities = []
        url = f'https://security-tracker.debian.org/tracker/source-package/{package}'
        
        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = bs(response.text, 'html.parser')
            
            # Find vulnerability table
            vuln_table = soup.find('table', {'class': 'data'})
            if vuln_table:
                for row in vuln_table.find_all('tr')[1:]:  # Skip header
                    cells = row.find_all('td')
                    if len(cells) >= 6:
                        vuln = Vulnerability(
                            bug_id=cells[0].text.strip(),
                            package=package,
                            version=cells[1].text.strip(),
                            urgency=self._parse_urgency(cells[2].text.strip()),
                            remote=self._is_remote_exploit(cells[3].text.strip()),
                            fix_available=self._has_fix(cells[4].text.strip()),
                            description=cells[5].text.strip()
                        )
                        vulnerabilities.append(vuln)
                        
            return vulnerabilities
        except Exception as e:
            print(f"Error checking vulnerabilities: {e}")
            return []

    def _parse_urgency(self, urgency: str) -> str:
        """Parse urgency level"""
        urgency = urgency.lower()
        if 'high' in urgency:
            return 'high'
        elif 'medium' in urgency:
            return 'medium'
        elif 'low' in urgency:
            return 'low'
        return 'unknown'

    def _is_remote_exploit(self, remote: str) -> bool:
        """Check if vulnerability is remotely exploitable"""
        return 'remote' in remote.lower()

    def _has_fix(self, status: str) -> bool:
        """Check if a fix is available"""
        return 'fixed' in status.lower()

    def generate_security_report(self, packages: List[Dict]) -> str:
        """
        Generate a comprehensive security report
        """
        report = []
        report.append("Security Analysis Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("-" * 50)
        
        vulnerable_count = 0
        fixed_count = 0
        
        for pkg in packages:
            vulns = self.check_package_vulnerabilities(pkg.get('Package', ''))
            if vulns:
                vulnerable_count += len(vulns)
                for vuln in vulns:
                    if vuln.fix_available:
                        fixed_count += 1
                    report.append(f"\nPackage: {vuln.package}")
                    report.append(f"Bug ID: {vuln.bug_id}")
                    report.append(f"Urgency: {vuln.urgency}")
                    report.append(f"Remote Exploit: {'Yes' if vuln.remote else 'No'}")
                    report.append(f"Fix Available: {'Yes' if vuln.fix_available else 'No'}")
                    report.append(f"Description: {vuln.description}")
                    report.append("-" * 30)
        
        report.insert(3, f"Total Vulnerabilities: {vulnerable_count}")
        report.insert(4, f"Fixes Available: {fixed_count}")
        
        return "\n".join(report)
def enhance_menu():
    """
    Enhanced menu with new security analysis options
    """
    menu = """
    [1] Fetch Debian Versions
    [2] Get CVE Information
    [3] View Resolved Issues
    [4] Check Installed Packages
    [5] Generate Security Report
    [6] Check Package Vulnerabilities
    [7] Exit Program
    """
    return menu

###########################################################


def print_banner():
    banner = """
    ╔═══════════════════════════════════════╗
    ║     Debian Security Tracker Tool      ║
    ║          Security Analysis            ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)
    
def print_menu():
    menu = """
    [1] Fetch Debian Versions
    [2] Get CVE Information
    [3] View Resolved Issues
    [4] Exit Program
    """
    print(menu)
    
def get_user_choice() -> Optional[int]:
    try:
        choice = int(input("\n[+] Enter your choice (1-7): "))
        if 1 <= choice <= 7:
            return choice
        print("\n[-] Invalid choice. Please select 1-7.")
        return None
    except ValueError:
        print("\n[-] Please enter a valid number.")
        return None

def fetch_debian_versions(url):
    try:
        # Make the request
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        print(f"Status code: {response.status_code}")

        # Parse the HTML
        soup = bs(response.text, 'html.parser')
        
        # Get the header
        header = soup.find('h2')
        if header:
            print(f"\n {header.text}\n")

        # Create and setup the table
        table = PrettyTable()
        table.field_names = ["Distribution", "Version", "Type"]
        table.align = "l"  # Left align

        # Get the first table and process its data
        first_table = soup.find('table')
        if first_table:
            rows = first_table.find_all('tr')
            current_dist = None
            
            for row in rows:
                cells = row.find_all('td')
                if cells:
                    # Process the cells and add to table
                    dist = cells[0].text.strip()
                    version = cells[1].text.strip()
                    
                    # Determine if it's a security update
                    is_security = "security" in dist.lower()
                    dist = dist.split()[0]  # Remove "(security)" if present
                    
                    table.add_row([
                        dist,
                        version,
                        "security" if is_security else "Stable"
                    ])

            print(table)
        else:
            print("No table found on the page")

    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
    except Exception as e:
        print(f"Error processing data: {e}")        
        
def fetch_debian_CVE(url):
    try:
        # Make the request
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        # Parse the HTML
        soup = bs(response.text, 'html.parser')
        
        # Find 2nd Header
        header = soup.find_all('h2')[1]
        print(f"\n{header.text}\n")

        # Second table for CVE
        second_table = soup.find_all('table')[1]
        if second_table:
            # Create and setup the table
            table = PrettyTable()
            table.field_names = ["CVE", "bullseye", "bookworm", "trixie", "sid", "Description"]
            table.align = "l"  # Left align
            table.max_width['Description'] = 40  # Limit description width
            
            # Process rows
            rows = second_table.find_all('tr')[1:]  # Skip header row
            for row in rows:
                cells = row.find_all(['td', 'th'])
                if cells:
                    # Extract CVE
                    cve_cell = cells[0].find('a')
                    cve = cve_cell.text.strip() if cve_cell else "N/A"
                    
                    # Extract status for each distribution
                    statuses = []
                    for cell in cells[1:5]:
                        status = cell.find('span')
                        status_text = status.text.strip() if status else "N/A"
                        statuses.append(status_text)
                    
                    # Extract description
                    description = cells[5].text.strip()
                    
                    # Add to table
                    table.add_row([
                        cve,
                        statuses[0],
                        statuses[1],
                        statuses[2],
                        statuses[3],
                        description
                    ])
            
            print(table)
        else:
            print("No CVE table found on the page")

    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
    except Exception as e:
        print(f"Error processing data: {e}")
        
def resolved_issue(url):
    try:
        # Make the request
        response = requests.get(url)
        response.raise_for_status()
        
        # Parse the HTML
        soup = bs(response.text, 'html.parser')
        
        # Find 3rd Header
        header = soup.find_all('h2')[3]
        print(f"\n{header.text}\n")

        # Third table for resolved issues
        third_table = soup.find_all('table')[3]
        if third_table:
            # Create and setup the table
            table = PrettyTable()
            table.field_names = ["Bug ID", "Description"]
            table.align = "l"
            table.max_width['Description'] = 60

            # Process rows
            rows = third_table.find_all('tr')[1:]  # Skip header row
            for row in rows:
                cells = row.find_all(['td'])
                if cells:
                    # Extract Bug ID
                    bug_cell = cells[0].find('a')
                    bug_id = bug_cell.text.strip() if bug_cell else "N/A"

                    # Extract description
                    description = cells[1].text.strip()

                    # Add to table
                    table.add_row([bug_id, description])

            print(table)
        else:
            print("No resolved issues table found on the page")

    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
    except Exception as e:
        print(f"Error processing data: {e}")

def main():
    analyzer = SecurityAnalyzer()
    url = 'https://security-tracker.debian.org/tracker/source-package/linux'
    
    print_banner()
    
    while True:
        print(enhance_menu())
        choice = get_user_choice()
        
        if choice is None:
            continue
            
        try:
            if choice == 1:
                fetch_debian_versions(url)
            elif choice == 2:
                fetch_debian_CVE(url)
            elif choice == 3:
                resolved_issue(url)
            elif choice == 4:
                packages = analyzer.check_installed_packages()
                print(analyzer.analyze_package_versions(packages))
            elif choice == 5:
                packages = analyzer.check_installed_packages()
                print(analyzer.generate_security_report(packages))
            elif choice == 6:
                package_name = input("Enter package name to check: ")
                vulns = analyzer.check_package_vulnerabilities(package_name)
                for vuln in vulns:
                    print(f"\nBug ID: {vuln.bug_id}")
                    print(f"Urgency: {vuln.urgency}")
                    print(f"Remote Exploit: {'Yes' if vuln.remote else 'No'}")
                    print(f"Fix Available: {'Yes' if vuln.fix_available else 'No'}")
                    print(f"Description: {vuln.description}")
            elif choice == 7:
                print("\n[+] Thank you for using the Debian Security Tracker Tool")
                print("[+] Exiting program...")
                sys.exit(0)
        except Exception as e:
            print(f"\n[-] An error occurred: {str(e)}")
        
        input("\nPress Enter to continue...")
        
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user")
        print("[+] Exiting gracefully...")
        sys.exit(1)
