from mininet.topo import Topo

class MyTopo(Topo):
	def build(self):
		#add switches
	    switch_s1=self.addSwitch('s1')

		#add hosts
	    host_h1=self.addHost('h1')
	    host_h2=self.addHost('h2')

		# add Links
	    self.addLink(host_h1, switch_s1)
	    self.addLink(host_h2, switch_s1)

	    print("***Start***")

topos = { 'mytopo' : ( lambda: MyTopo() )}

