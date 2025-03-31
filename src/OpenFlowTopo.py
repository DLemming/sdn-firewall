from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCIntf

class FirewallTopo(Topo):

    __LINK_BANDWIDTH = 1

    def __init__(self):
        Topo.__init__(self)    

    def build(self):
        # Switch erstellen
        switch = self.addSwitch('s1')

        # Drei Hosts in unterschiedlichen Subnetzen erstellen
        host1 = self.addHost('h1', ip='10.0.0.1/24', mac='ba:de:af:fe:00:01')
        host2 = self.addHost('h2', ip='10.0.0.2/24', mac='ba:de:af:fe:00:02')
        host3 = self.addHost('h3', ip='10.0.0.3/24', mac='ba:de:af:fe:00:03')

        # Verbindung zwischen Hosts und Switch erstellen 
        for host in [host1, host2, host3]:
            self.addLink(host, switch,
                         cls1=TCIntf, cls2=TCIntf,
                         intfName1=host + '-' + switch,
                         intfName2=switch + '-' + host,
                         params1={'bw': self.__LINK_BANDWIDTH},
                         params2={'bw': self.__LINK_BANDWIDTH})

def run():
    # Mininet mit Remote-Controller starten
    topo = FirewallTopo()
    net = Mininet(topo=topo, controller=RemoteController('ofp-c1', ip='127.0.0.1', port=6653))
    net.start()
    
    print("Firewall Topology started. You can now configure the OpenFlow rules in your controller.")
    
    CLI(net)  # Interaktive Shell starten
    net.stop()

if __name__ == '__main__':
    run()