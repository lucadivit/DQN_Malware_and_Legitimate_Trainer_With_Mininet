
class PacketFilter():

    def __init__(self, ip_whitelist_filter=[], ip_blacklist_filter=[], IPv4=False, TCP=False, UDP=False):
        self.packets_list = []
        self.ip_whitelist_filter = ip_whitelist_filter
        self.ip_blacklist_filter = ip_blacklist_filter
        self.IPv4 = IPv4
        self.TCP = TCP
        self.UDP = UDP
        if(len(self.ip_whitelist_filter) > 0 or len(self.ip_blacklist_filter) > 0):
            self.set_IPv4_filter(True)

    def clean_list(self, packet_list):
        new_list = []
        for pkt in packet_list:
            if(self.add_packet_to_list(pkt) is True):
                new_list.append(pkt)
            else:
                pass
        return new_list

    def check_packet_filter(self, pkt):

        results = []

        def IPv4_filter(pkt):
            if(pkt.haslayer("IP")):
                return True
            else:
                return False

        def ip_blacklist_filter(pkt, check_list):
            if(IPv4_filter(pkt) is True):
                if(len(check_list) > 0):
                    if(pkt["IP"].src not in check_list):
                        return True
                    else:
                        return False
                else:
                    return True
            else:
                return False

        def ip_whitelist_filter(pkt, check_list):
            if(IPv4_filter(pkt) is True):
                if(len(check_list) > 0):
                    if(pkt["IP"].src in check_list):
                        return True
                    else:
                        return False
                else:
                    return True
            else:
                return False

        def UDP_filter(pkt):
            if(pkt.haslayer("UDP")):
                return True
            else:
                return False

        def TCP_filter(pkt):
            if(pkt.haslayer("TCP")):
                return True
            else:
                return False

        if(self.get_IPv4_filter() is True):
            results.append(IPv4_filter(pkt))
        if(len(self.get_ip_blacklist_filter()) > 0):
            results.append(ip_blacklist_filter(pkt, self.get_ip_blacklist_filter()))
        if(len(self.get_ip_whitelist_filter()) > 0):
            results.append(ip_whitelist_filter(pkt, self.get_ip_whitelist_filter()))
        if(self.get_TCP_filter() is True):
            results.append(TCP_filter(pkt))
        if(self.get_UDP_filter() is True):
            results.append(UDP_filter(pkt))
        if(False in results):
            return False
        else:
            return True

    def set_packet_list(self, packet_list):
        self.packets_list = packet_list

    def set_IPv4_filter(self, val):
        self.IPv4 = val

    def set_ip_whitelist_filter(self, ip_filter):
        self.ip_whitelist_filter = ip_filter

    def set_ip_blacklist_filter(self, ip_filter):
        self.ip_blacklist_filter = ip_filter

    def set_TCP_filter(self, val):
        self.TCP = val

    def set_UDP_filter(self, val):
        self.UDP = val

    def get_TCP_filter(self):
        return self.TCP

    def get_UDP_filter(self):
        return self.UDP

    def get_packet_list(self):
        return self.packets_list

    def get_IPv4_filter(self):
        return self.IPv4

    def get_ip_whitelist_filter(self):
        return self.ip_whitelist_filter

    def get_ip_blacklist_filter(self):
        return self.ip_blacklist_filter