from ouimeaux.environment import Environment
from scapy.all import *  # scapy only supports Python 2


def callback(pkt):
    # noinspection PyUnresolvedReferences
    p = pkt[ARP]
    if p.op == 1:  # and p.psrc == "0.0.0.0":
        if p.hwsrc == "68:37:e9:ec:20:51":
            print "ARP Probe from: {0}".format(p.hwsrc)
            # subprocess.call("run.bat")
        if p.hwsrc == "0c:47:c9:88:63:b7":
            print "ARP Probe from: {0}".format(p.hwsrc)
            kitten_lamp.off() if kitten_lamp.get_state() == 1 else kitten_lamp.on()

if __name__ == "__main__":
    wemo_env = Environment()
    wemo_env.start()
    wemo_env.discover(5)
    kitten_lamp = wemo_env.get_switch("Kitten Desk Lamp")

    print "Sniffing now at {0}".format(time.strftime("%H:%M", time.localtime()))
    sniff(prn=callback, filter="arp", store=0)
