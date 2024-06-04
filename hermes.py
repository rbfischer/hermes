#!/usr/bin/env python3
import os
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
import zipfile
import json
import dns.resolver
import argparse
import datetime
import concurrent.futures
import socket
import contextlib
import re
import ssl

# Global settings defined here
#
try: 
    scb, token = os.environ["ASTRA_DB_SECURE_BUNDLE_PATH"], os.environ["ASTRA_DB_APPLICATION_TOKEN"]
except:
    scb, token = None, None

# Instantiate Report object
report = []

# Big strings...
application_name = os.path.basename(__file__)
description = '''    A tool to test connectivity to Astra databases. 
    Requires the ASTRA_DB_SECURE_BUNDLE_PATH and ASTRA_DB_APPLICATION_TOKEN environment variables to be set. 
    Flags may be set in any order. 
    A report is printed at the end of the test run unless the --live flag is set.
    '''
epilog = f'''Example usage: 
    ASTRA_DB_SECURE_BUNDLE_PATH=/path/to/secure-connect-bundle.zip ASTRA_DB_APPLICATION_TOKEN="AstraCS:..." python {application_name} 
    ASTRA_DB_SECURE_BUNDLE_PATH=/path/to/secure-connect-bundle.zip ASTRA_DB_APPLICATION_TOKEN="AstraCS:..." python {application_name} --debug --live 
    ASTRA_DB_SECURE_BUNDLE_PATH=/path/to/secure-connect-bundle.zip ASTRA_DB_APPLICATION_TOKEN="AstraCS:..." python {application_name} --debug --save report.txt --force
    '''

# Input flags
parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-s", "--save", help="Saves the output to a file", type=str)
parser.add_argument("-f", "--force", help="Force-save file", action="store_true")
parser.add_argument("-d", "--debug", help="Enables collecting additional information", action="store_true")
parser.add_argument("-l", "--live", help="Output to STDOUT instead of printing final report", action="store_true")
parser.add_argument("-c", "--show-config", help="Show the SCB config.json", action="store_true")
parser.add_argument("-cs", "--show-config-sensitive", help="Show the SCB config.json without redacting JKS passwordss", action="store_true")
args = parser.parse_args()

## Store reusable functions here ##
@staticmethod
def timeprint(*args):
    print(datetime.datetime.utcnow().isoformat(sep=" ", timespec="seconds"), "UTC", *args)

@staticmethod
def separator(char, count):
    return char * count
    
@staticmethod
def saveFile(path, data):
    with open(path, 'w') as f:
        f.write(data)
    return True

def addreport(*line):
    if args.live:
        print(*line)
    report.append(*line)

def printReport():
    for line in report:
        print(line)

def printSCB(config):
    print(json.dumps(config, indent=4))

def read_secure_connect_bundle(sensitive):
    config = None
    with zipfile.ZipFile(scb) as z:
      with z.open('config.json') as configfile:
          config = json.loads(configfile.read())
    if sensitive:
        redacted = "[Redacted]"
        config['keyStorePassword'] = redacted
        config['trustStorePassword'] = redacted
        config['pfxCertPassword'] = redacted
    return config

## End reusable functions ##

## Tests ##
def testDNS(url):
    addreport(separator('=', 10))
    addreport("DNS Test:")
    try:
        result = dns.resolver.resolve(url, 'A')
    except Exception as e:
        addreport("DNS resolution failed. Error:", e)
        return False
    if result:
        addreport(f"Resolved {result.__len__()} IP addresses for {url}")
        if args.debug:
            addreport(separator('=', 4))
            for val in result:
                addreport(val.to_text())
            addreport(separator('=', 4))
        return result

def testPorts(config, records):
    results = {}
    addreport(separator('=', 10))
    addreport("Port Connectivity Test:")
    def contact(args):
        ip, port = args
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, int(port)))
            s.shutdown(2)
            return (ip, port, True)
        except Exception as e:
            return (ip, port, False)

    ports = [config['port'], config['cql_port']]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(contact, (i.to_text(), p)): (i.to_text(), p) for i in records for p in ports}
        for future in concurrent.futures.as_completed(futures):
            ip, port, result = future.result()
            if ip not in results:
                results[ip] = {}
            results[ip][port] = result
    count = 0
    if args.debug:
        addreport(separator('=', 4))
    for ip, ports in results.items():
        for port, result in ports.items():
            if result:
                if args.debug:
                    addreport(f"Connection to {ip} on port {port} successful")
            else:
                if args.debug:
                    addreport(f"Error: No response from {ip} on port {port}")
                count += 1
    if args.debug:
        addreport(separator('=', 4))
    if count > 0:
        addreport(f"Error: Some connections failed. Resuming...")
        return True
    if count == results.__len__():
        addreport("Error: All connections failed. Ending tests.")
        return False
    else:
        addreport("All connections successful")
        return True

def testLatency(records, interval, count):
    latency = {}
    addreport(separator('=', 10))
    addreport("Latency Test:")
    def get_latency(i):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        start_time = datetime.datetime.now()
        try:
            sock.connect((i.to_text(), 29042))
            sock.close()
            end_time = datetime.datetime.now()
            return i, ((end_time - start_time).total_seconds() * 1000)
        except:
            return i, 9999

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(get_latency, i): i for i in records}
        for future in concurrent.futures.as_completed(futures):
            i, avg_rtt = future.result()
            latency[i] = avg_rtt
    if args.debug:
        addreport(separator('=', 4))
        for key, value in latency.items():
            lat = round(value, 2)
            addreport(f"Latency to {key} is {lat} ms")
        addreport(separator('=', 4))
    avglat = round(sum(latency.values()) / len(latency), 2)
    addreport(f"Average latency to contact points is {avglat} ms")
    return

def testPL(records):
    # If the resolved IP conforms to RFC1918, it is a PrivateLink IP
    pl = {}
#    addreport(separator('=', 10))
    for ip in records:
        if re.match(r'^10\.', ip.to_text()) or re.match(r'^192\.168\.', ip.to_text()) or re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip.to_text()):
            pl[ip] = True
        else:
            pl[ip] = False
    count = 0
    for val in pl:
        if val == True:
            count += 1
    if count == pl.__len__():
        addreport("PrivateLink detected")
        return True
    elif count == 0:
        addreport("No PrivateLink detected")
        return False
    else:
        # It's extremely difficult to run into this issue, but it's completely user-error.
        addreport("Error: Some IPs are PrivateLink, some are not")
        return False
    
def testAuth():
    addreport(separator('=', 10))
    addreport("Testing authentication")
    try:
        session = Cluster(connect_timeout = 2, cloud={"secure_connect_bundle": scb}, auth_provider=PlainTextAuthProvider("token", token),).connect()
        row = session.execute("select release_version from system.local", trace=True)
    except Exception as e:
        addreport("Authentication failed. Error:", e)
        return False
    rez = row.one()
    if rez:
        if args.debug:
            addreport(f"Request read latency: {round(row.get_query_trace().duration.total_seconds() * 1000, 2)} ms")
        addreport("Authentication successful")
        return False
    else:
        addreport("Authentication failed. Please check your credentials and/or Secure Connect Bundle.")
        return False
    session.shutdown()

## End tests ##
    
## All tests are run from here ##
def astraTests():
    config = read_secure_connect_bundle(True)
    records = testDNS(config["host"])
    if not records:
        return False
    testPL(records)
    if not testPorts(config, records):
        return False
    testLatency(records, 1, 5)
    testAuth()
    
    # Closing report
    addreport(separator('=', 10))
    return True


# Main run
def main():
    exit = 0
    # Checking if the Environment Variables have been set
    if not scb or not token:
        print("Error: Please set both the ASTRA_DB_SECURE_BUNDLE_PATH and ASTRA_DB_APPLICATION_TOKEN environment variables and run the application again.")
        os._exit(1)

    # You may begin your test run now
    timeprint("Tests Start")
    if not astraTests():
        print("Tests failed.")
        if not args.live:
            printReport()
        exit = 1
    
    if args.save:
        print("Saving report to file")
        now = f"{datetime.datetime.utcnow().isoformat(sep=' ', timespec='seconds')} UTC"
        header = f"Astra Connection Test Report\n{now}\n{separator('-', 10)}\n"
        if os.path.exists(args.save):
            if not args.force:
                overwrite = input(f"File {args.save} already exists. Overwrite? (Y/N) ")
                if overwrite.lower() != 'y':
                    print("Not overwriting existing file. Exiting.")
                    return
        saveFile(args.save, header + "\n".join(report))
        return

    # It's rare for this to be necessary:
    if args.show_config|args.show_config_sensitive:
        print("printing config.json from SCB: ", scb)
        if args.show_config_sensitive:
            printSCB(read_secure_connect_bundle(False))
        else:
            printSCB(read_secure_connect_bundle(True))
    
    if args.live:
        timeprint("Done. Exiting...")  
    if not args.live:
        timeprint("Printing report:")
        printReport()
    os._exit(exit)

if __name__ == "__main__":
    main()