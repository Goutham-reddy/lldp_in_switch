from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

def mycmd( self, line ):
    "Start LLDP Protocol"
    net = self.mn
    print( 'mycmd invoked for', net, 'with line', line, '\n'  )
    names = net.keys() 
    for temp in names:
       temp1 = temp.startswith('s')
       if temp1 == True:
	  name1 = net.get(temp) 
	  switch_id = temp[1:]
	  print switch_id
          name1.sendCmd('sudo java -cp gtest.jar:./lib/* lldpspeaker.LLDPSpeaker ' + switch_id)
    
    
CLI.do_mycmd = mycmd
