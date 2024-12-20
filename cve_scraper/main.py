import sys
from typing import Optional
from bs4 import BeautifulSoup as bs
import requests
from prettytable import PrettyTable


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
        choice = int(input("\n[+] Enter your choice (1-4): "))
        if 1 <= choice <= 4:
            return choice
        print("\n[-] Invalid choice. Please select 1-4.")
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
            table.max_width['Description'] = 60  # Limit description width
            
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
        response.raise_for_status()  # Raise an exception for bad status codes
        
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
            table.align = "l"  # Left align
            table.max_width['Description'] = 60  # Limit description width for readability
            
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
    url = 'https://security-tracker.debian.org/tracker/source-package/linux'
    
    print_banner()
    
    while True:
        print_menu()
        choice = get_user_choice()
        
        if choice is None:
            continue
            
        if choice == 1:
            fetch_debian_versions(url)
        elif choice == 2:
            fetch_debian_CVE(url)
        elif choice == 3:
            resolved_issue(url)
        elif choice == 4:
            print("\n[+] Thank you for using the Debian Security Tracker Tool")
            print("[+] Exiting program...")
            sys.exit(0)
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user")
        print("[+] Exiting gracefully...")
        sys.exit(1)