from builtins import super
from threading import Event
from scapy.layers.inet import IP
from scapy.all import *
import os

class Sniffer(Thread):

    mtu = 2500

    def __init__(self, interface, callback_prn=None, callback_stop=None, stop_escape_raw="stop_sniff", monitor=False, verbose=False, callback_prn_kwargs = {}, callback_stop_kwargs = {}):
        super().__init__()
        self.interface = interface
        self.stop_escape_raw = stop_escape_raw
        self.callback_stop = callback_stop
        self.callback_prn = callback_prn
        self.is_stopped = False
        self.is_started = False
        self.monitor = monitor
        self.verbose = verbose
        self.stop_sniffer_flag = Event()
        self.callback_prn_kwargs = callback_prn_kwargs
        self.callback_stop_kwargs = callback_stop_kwargs

    def start(self):
        super().start()

    def run(self):
        self.check_mtu()
        try:
            print("\n" + "Sniffer Avviato" + "\n")
            self.set_started_flag(True)
            self.set_stopped_flag(False)
            sniff(iface=self.get_interface().get_interface_name(), prn=self.sniffing_callback, store=0,  stop_filter=self.stop_callback, monitor=self.get_monitor())#lambda x: self.stop_sniffer_flag.isSet()
        except Exception as e:
            print(e)
        return

    def check_mtu(self):
        default_mtu = self.get_interface().get_mtu()
        if(self.mtu > default_mtu):
            print("La tua MTU e' " + str(default_mtu) + ". Si consiglia di portarla a 2500.")
        else:
            pass
        return

    def set_started_flag(self, bool_flag):
        self.is_started = bool_flag

    def get_started_flag(self):
        return self.is_started

    def set_stopped_flag(self, bool_stop):
        self.is_stopped = bool_stop

    def get_stopped_flag(self):
        return self.is_stopped

    def set_interface(self, interface):
        self.interface = interface

    def get_interface(self):
        return self.interface

    def set_monitor(self, val):
        self.monitor = val

    def get_monitor(self):
        return self.monitor

    def set_mtu(self, mtu):
        self.mtu = mtu

    def get_mtu(self):
        return self.mtu

    def set_stop_escape_raw(self, stop_escape_raw):
        self.stop_escape_raw = stop_escape_raw

    def get_stop_escape_raw(self):
        return self.stop_escape_raw

    def set_callback_stop(self, callback_stop, kwargs = {}):
        self.callback_stop = callback_stop
        self.callback_stop_kwargs = kwargs

    def set_callback_prn(self, callback_prn, kwargs = {}):
        self.callback_prn = callback_prn
        self.callback_prn_kwargs = kwargs

    def set_callback_prn_kwargs(self, kwargs):
        self.callback_prn_kwargs = kwargs

    def get_callback_prn_kwargs(self):
        return self.callback_prn_kwargs

    def set_callback_stop_kwargs(self, kwargs):
        self.callback_stop_kwargs = kwargs

    def get_callback_stop_kwargs(self):
        return self.callback_stop_kwargs

    def stop(self):
        self.stop_sniffer_flag.set()
        sendp(IP(src="127.0.0.1", dst="127.0.0.1")/self.get_stop_escape_raw(), verbose=0, iface=self.get_interface().get_interface_name())

    def set_verbose(self, val):
        self.verbose=val

    def get_verbose(self):
        return self.verbose

    def sniffing_callback(self, *args):
        if self.is_last_packet(args[0]) is True:
            pass
        else:
            if self.callback_prn is not None:
                self.callback_prn(*args[0], **self.get_callback_prn_kwargs())
            if self.get_verbose() is True:
                print("\n" + "Pkt sniffato" + "\n")

    def is_last_packet(self, pkt):
        if pkt[0].haslayer(Raw) is True and self.stop_sniffer_flag.isSet() is True:
            payload = str(pkt[0].getlayer(Raw).load)
            if self.stop_escape_raw in payload:
                return True
            else:
                return False
        else:
            return False

    def stop_callback(self, *args):
        if self.is_last_packet(args[0]) is True:
            if self.callback_stop is not None:
                self.callback_stop(*args[0], **self.get_callback_stop_kwargs())
                self.set_stopped_flag(True)
                self.set_started_flag(False)
            print("\n" + "Sniffer Terminato" + "\n")
            return True
        else:
            return False