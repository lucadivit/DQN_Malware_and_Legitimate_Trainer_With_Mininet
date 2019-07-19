import socket
import struct
import subprocess
from fcntl import ioctl

class Iface:

    SIOCGIFMTU = 0x8921

    SIOCSIFMTU = 0x8922

    default_mtu = 1500

    def __init__(self, ifname):

        self.ifname = ifname
        self.old_mtu = self.get_mtu()

    def get_mtu(self):
        '''Use socket ioctl call to get MTU size'''
        s = socket.socket(type=socket.SOCK_DGRAM)
        ifr = self.ifname + '\x00'*(32-len(self.ifname))
        try:
            ifs = ioctl(s, self.SIOCGIFMTU, ifr)
            mtu = struct.unpack('<H',ifs[16:18])[0]
        except Exception as s:
            print('socket ioctl call failed: {0}'.format(s))
            mtu = None
        return mtu

    def set_mtu(self, mtu):
        '''Use socket ioctl call to set MTU size'''
        s = socket.socket(type=socket.SOCK_DGRAM)
        ifr = struct.pack('<16sH', self.ifname.encode('utf-8'), mtu) + '\x00'.encode('utf-8')*14
        try:
            ifs = ioctl(s, self.SIOCSIFMTU, ifr)
            mtu = struct.unpack('<H',ifs[16:18])[0]
            setted = True
        except Exception as s:
            print('socket ioctl call failed: {0}'.format(s))
            setted = False
        return setted

    def get_default_mtu(self):
        return self.default_mtu

    def restore_mtu(self):
        self.set_mtu(self.old_mtu)

    def get_interface_name(self):
        return self.ifname

    def set_interface_name(self, ifname):
        self.ifname = ifname