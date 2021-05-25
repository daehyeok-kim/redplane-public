from scapy.all import *
import sys

print(sys.argv[1])
packets = rdpcap(sys.argv[1], count = 100)
out_file = open('m57_summary.txt',"w")
ip_list = []
tcp_flows = []
udp_flows = []
total = 0
for packet in packets:
    print (packet.time)
    if packet.haslayer(IP) and packet.haslayer(TCP):
        total += 1 
        flow_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
        if flow_key not in tcp_flows:
            tcp_flows.append(flow_key)
    elif packet.haslayer(IP) and packet.haslayer(UDP):
        total += 1
        flow_key = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport)
        if flow_key not in udp_flows:
            udp_flows.append(flow_key)
    if packet.haslayer(TCP) and packet[IP].src.find('192.168') != -1:
        if packet[IP].dst not in ip_list:
            ip_list.append(packet[IP].dst)
        out_file.write('%s %d %d %d\n'%(packet[IP].dst, packet[TCP].sport, packet[TCP].dport, packet[IP].len))
    if packet.haslayer(TCP) and packet[IP].dst.find('192.168') != -1:
        print (packet.show())
        #if packet[IP].dst not in ip_list:
        #    ip_list.append(packet[IP].dst)
        #out_file.write('%s %d %d %d\n'%(packet[IP].dst, packet[TCP].sport, packet[TCP].dport, packet[IP].len))
print ("Unique dest IP: %d" % len(ip_list))
print ("UDP flows: %d"%(len(udp_flows)))
print ("TCP flows: %d"%(len(tcp_flows)))
print ("Total packets: %d"%(total))