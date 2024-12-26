from scapy.all import sniff

# This function will be called for each packet
def packet_callback(packet):
    print(packet.summary())

# Start sniffing packets (captures all packets)
def start_sniffing(interface=None, count=10):
    # Sniff 10 packets on the given interface (or default interface)
    sniff(iface=interface, count=count, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Optionally, specify an interface (e.g., 'eth0' or 'wlan0')
    # For Windows, use 'Ethernet' or 'Wi-Fi' or leave as None for default interface
    interface = None  # Example: "eth0" or "Wi-Fi"
    
    # Start sniffing 10 packets (you can increase the count as needed)
    start_sniffing(interface=interface, count=10)
