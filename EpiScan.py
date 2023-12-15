
#BannerUI
import pyfiglet
#Create Socket
import socket
#Create network requests with asynchronously execution
import concurrent.futures
#Get Time from system
from datetime import datetime
import nmap

def scan_specific_ports(target, ports):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-p ' + ','.join(ports))

        for host in nm.all_hosts():
            print(f"Host: {host}")
            for port, state in nm[host]['tcp'].items():
                print(f"Port: {port}, State: {state['state']}")
    except Exception as e:
        print(f"Scanning failed: {e}")

def scan_port(target, port):
    try:
        #socket.AF_INET     : socket adress family which is used for ipv4 addresses
        #socket.SOCK_STREAM : socket type which is used for tcp connections
        #Create Socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #this means the function will give up after 1 second if it cannot establish a connection .
        socket.setdefaulttimeout(1)
        #Connect-ex method returns 0 if the connection is successfully established however if it fails , it will return non zero
        result = s.connect_ex((target, port))
        #if the result returned from the previous instruction 0 thats mean port is open otherwise there is nothing happend
        if result == 0:
            print(f"Port {port} is open")
        s.close()
        #nothing happen when error occurs
    except socket.error:
        pass

def detect_os(target):
    try:
        # Create an instance of the nmap PortScanner class
        nm = nmap.PortScanner()

        # Perform an OS detection scan
        nm.scan(target, arguments='-O')

        # Check if the OS detection results are available
        if target in nm.all_hosts() and 'osmatch' in nm[target]:
            os_matches = nm[target]['osmatch']
            print("OS Detection Results:")
            for match in os_matches:
                print(f"Name: {match['name']}, Accuracy: {match['accuracy']}%")
        else:
            print("OS detection failed")

    except Exception as e:
        print(f"OS detection failed: {e}")


def Service_Version_Detection(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV ')

        for host in nm.all_hosts():
            for port, state in nm[host]['tcp'].items():
                service_version=state['version']
                service_name=state['name']
                print(f"Host: {host}")
                print(f"Port: {port}, State: {state['state']}")
                print(f"Service_name: {service_name}")
                print(f"Service_Version: {service_version}")

    except Exception as e:
            print(f"Something Wrong: {e}")


def Banner () :
    ascii_banner = pyfiglet.figlet_format("EPISCAN",font="banner3-D")
    print(ascii_banner)


def Scan_all_Ports(target) :
    #concurrent.futures module in Python scan a range of ports (1 to 65535) using a thread pool of 1000
    #ThreadPoolExecutor class that creates a pool of threads to execute tasks asynchronously
    #Scan whole range of ports by submitting a thread pool of 1000 threads that takes the target ip and scan_port function that creates socket for ipv4 adrees and tcp connection
    with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
        [executor.submit(scan_port, target, port) for port in range(1, 65536)]



def main():
    # other fonts : banner3-D == alphabet ==  5lineoblique == isometric1 == bulbhead
    #Banner Font
    Banner()
    #ip address
    target = input("Target IP Address ==> ")
    #BannerUI
    print ("-- Choose if you want to make either Full Scan or Specific Scan ---")
    print("1 -- Full Scan (65536 ports)")
    print("2 -- Specific Ports ---")
    choice = int(input(""))
    print("-" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at: " + str(datetime.now()))
    print("-" * 50)
    if choice == 1 :
        print("it will take sometime to finish")
        Scan_all_Ports(target)
        detect_os(target)
        Service_Version_Detection(target)
        print("\nScanning completed at:" + str(datetime.now()))
    elif choice == 2 :
        ports = []
        port_number = int (input("how many ports do you want to scan  :"))
        for i in range (port_number) :
            port = input("==> ")
            ports.append(port)
        print("-" * 50)
        print("Scanning Target: " + target)
        print("Scanning started at: " + str(datetime.now()))
        print("-" * 50)
        scan_specific_ports(target, ports)
        detect_os(target)
        Service_Version_Detection(target)
        print("\nScanning completed at:" + str(datetime.now()))

#if __name__ == "__main__":
main()
