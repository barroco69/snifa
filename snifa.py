import os
import nmap
import glob
import time
import socket
import sqlite3
import pyfiglet
import subprocess
from datetime import datetime

# ANSI escape codes for text colors
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
#print(colors.RED + "This is red text." + colors.RESET)

def scandata():
    socket.setdefaulttimeout(0.01)
    ip = input("IP ADDRESS: ")
    startPort = int(input("START PORT: "))
    endPort = int(input("END PORT: "))
    scan_remote_host(ip, startPort, endPort)


def scan_remote_host(ip, startPort, endPort):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n")
    print("-" * 50)
    print("Scan started at: %s" % time)

    nm = nmap.PortScanner()
    host_antigo = ""
    # Perform a basic ping scan to identify live hosts
    nm.scan(hosts=ip, arguments='-sn')

    # Iterate through the scanned hosts
    for host in nm.all_hosts():
        # Perform a detailed scan on open ports
        print("-" * 50)
        print(colors.BLUE + f"HOST: {host}" + colors.RESET)

        # Retrieve MAC information
        try:
            mac_address = nm[host]['addresses']['mac']
            print(f"MAC: {mac_address}")
        except KeyError:
            print("MAC: not available")
            mac_address = "Not available"
        
        nm.scan(hosts=host, arguments="-p %d-%d -sS -sC -sV -O" % (startPort, endPort))

        # Retrieve OS information
        try:
            os_matches = nm[host]['osmatch']
            if os_matches:  # Check if the list is not empty
                os_info = os_matches[0]['name']
                print(f"OS: : {os_info}")
            else:
                print("OS: not available")
                os_info = "Not available"
        except KeyError:
            print("OS: not available")
            os_info = "Not available"

        print("-" * 50)
        print("Open Port\tService\t\tVersion")
        print("-" * 50)

        for proto in nm[host].all_protocols():
            save_to_sqlite(time, host, mac_address, 0, "", os_info)
            # Iterate through open ports
            for port in sorted(nm[host][proto].keys()):
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                print(f"{port}\t\t{service}\t\t{version}")
                save_to_sqlite("", "", "", port, service, version)
    print("\nOutput saved to DB\nCreating Visual Report with all data...")
    # Convert time string to a datetime object
    time_tmp = datetime.strptime(time, "%Y-%m-%d %H:%M:%S")

    # Convert datetime object to the desired format ("%Y%m%d%H%M%S")
    timestamp = time_tmp.strftime("%Y%m%d%H%M%S")

    # Perform the Nmap scan without the -oA option
    nm.scan(ip, arguments="-p %d-%d -sS -sC -sV -O --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl" % (startPort, endPort))

    # Get the XML output after the scan
    xml_output = nm.get_nmap_last_output()

    # Write the XML output to a file with the timestamp as part of the filename
    output_filename = f"nmap_{timestamp}.xml"
    with open(output_filename, "wb") as file:
        file.write(xml_output)

    input("\nAll done!\nFile %s created." % output_filename)
    input(colors.GREEN + "\nPress Enter to continue..." + colors.RESET)


def save_to_sqlite(time, ip, mac_address, port, service, version):
    connection = sqlite3.connect("scan_results.db")
    cursor = connection.cursor()
    # Create a table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            ip TEXT,
            mac TEXT,
            port INTEGER,
            service_info TEXT,
            version TEXT
        )
    ''')
    # Insert data into the table
    cursor.execute('''
        INSERT INTO scan_results (time, ip, mac, port, service_info, version)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (time, ip, mac_address, port, service, version))
    # Commit the changes and close the connection
    connection.commit()
    connection.close()


def read_from_db():
    connection = sqlite3.connect("scan_results.db")
    cursor = connection.cursor()
    # Execute a SELECT query to retrieve data
    cursor.execute("SELECT * FROM scan_results")
    rows = cursor.fetchall()
    # Display the data
    print("-" * 115)
    print("ID\tTIME\t\t\tIP\t\tMAC\t\tOpen Port\tService\t\t\tVersion")
    print("-" * 115)
    for row in rows:
        print("%-5d %-20s %-15s %-20s %-15d %-20s %-15s" % (row[0], row[1], row[2], row[3], row[4], row[5], row[6]))
    # Close the connection
    connection.close()
    input(colors.GREEN + "\nPress Enter to continue..." + colors.RESET)


def view_visual_report():
    # Get the current value of the DISPLAY environment variable
    display = os.environ.get('DISPLAY')

    # Check if DISPLAY is None or empty
    if not display:
        print("Error: DISPLAY environment variable is not set.")
        exit(1)

    # Create a list of files starting with "nmap_"
    file_list = glob.glob("nmap_*")

    # Display the list of files to the user
    print("List of files starting with 'nmap_':")
    for i, file in enumerate(file_list, 1):
        print(f"{i}. {file}")

    # Ask the user to select a file
    selection = input("Enter the number of the file you want to open: ")

    try:
        # Convert the selection to an integer index
        index = int(selection) - 1
        
        # Check if the index is within the range of the file_list
        if 0 <= index < len(file_list):
            # Get the selected file
            selected_file = file_list[index]
            
            # Get the username of the user who invoked sudo
            sudo_user = os.environ.get('SUDO_USER')
            
            # Open the selected file in the default browser
            # Launching the browser as the current user without sudo
            # Create the command to open the file with xdg-open using the original user
            command = ["su", sudo_user, "/usr/bin/xdg-open", selected_file]
            # Set the DISPLAY environment variable for the subprocess
            env = os.environ.copy()
            env['DISPLAY'] = display
            
            # Execute the command
            subprocess.run(command, env=env)
            input(colors.GREEN + "\nPress Enter to continue..." + colors.RESET)
        else:
            print(colors.RED + "Invalid selection. Please enter a valid number." + colors.RESET)
            time.sleep(1)
    except ValueError:
        print(colors.RED + "Invalid input. Please enter a number." + colors.RESET)
        time.sleep(1)
        

def menu():
    os.system('clear')
    menu = {
    '1': "Start Scan",
    '2': "View Visual Report",
    '3': "Read DB",
    '4': "Exit"
    }

    while True:
        os.system('clear')
        print(colors.YELLOW + pyfiglet.figlet_format("SNIFA! SNIFA...") + colors.RESET)
        options = sorted(menu.keys())
        for entry in options:
            print(entry, menu[entry])
        selection = input("\nPlease select an option: ")
        if selection == '1':
            print("\n")
            print("-" * 22)
            print("|  Host/Range Scan   |")
            print("| ex: 192.168.1.1    |")
            print("| ex: 192.168.1.0/24 |")
            print("-" * 22)
            scandata()
        elif selection == '2':
            print("\n")
            print("-" * 22)
            print("| View Visual Report |")
            print("-" * 22)
            view_visual_report()
        elif selection == '3':
            print("\n")
            print("-" * 11)
            print("| Show DB |")
            print("-" * 11)
            read_from_db()
        elif selection == '4':
            print("\nHave a nice day!")
            break
        else:
            print(colors.RED + "Unknown option selected! Please try again." + colors.RESET)
            time.sleep(1)


menu()