# Task 02
# TODO 
#   be able to interrupt the connection (ssh) bt src and dst
#       send a package with RST flag to dst?
#   be able to slow down the connection bt src and dst
#       sniff pkt from src to dst and resend it with same ack number?

# imports
import scapy.all as sc


def Throttling_TCP(src_ip, dst_ip):
    def src_dest_filter(pkt):
        if sc.IP in pkt and sc.TCP in pkt:
            if pkt[sc.IP].src == src_ip and pkt[sc.IP].dst == dst_ip:
                return True
        return False
    
    p = sc.sniff(count=2, lfilter=src_dest_filter)
    print(p)
    for t in p:
        print(t)
    print(p[0])

if __name__ == '__main__':
    Throttling_TCP(src_ip='192.168.1.68', dst_ip='192.168.1.46')