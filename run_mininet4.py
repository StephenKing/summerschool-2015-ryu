#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def emptyNet():

    net = Mininet( topo=None, build=False )

    info( '*** Adding controller\n' )
    net.addController('c0', controller=RemoteController,ip="127.0.0.1",port=6633)
    h0 = net.addHost('h0', ip='127.0.0.1')

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'h1', ip='10.0.2.1', mac='00:00:00:00:00:01')
    h2 = net.addHost( 'h2', ip='10.0.2.2', mac='00:00:00:00:00:02' )

    info( '*** Adding switch\n' )
    s1 = net.addSwitch( 's1', cls=OVSSwitch )
    s2 = net.addSwitch( 's2', cls=OVSSwitch )
    s3 = net.addSwitch( 's3', cls=OVSSwitch )
    s4 = net.addSwitch( 's4', cls=OVSSwitch )

    info( '*** Creating links\n' )
    ## controller - switch (s4)
    net.addLink( h0, s4 )

    ## host - switch
    net.addLink( h1, s1 )
    net.addLink( h2, s3 )

    ## switches
    switchList = (s1, s2, s3, s4)
    for index in range (0, len(switchList)):
      for index2 in range (index+1, len(switchList)):
        #info( '(' + str(switchList[index]) + ',' + str(switchList[index2]) + ') ')
        net.addLink(switchList[index], switchList[index2])

    info( '\n*** Starting network\n')
    net.start()

    #info('*** Set ip address to switch\n')
    s1.cmd('ifconfig s1 10.0.1.1')
    s2.cmd('ifconfig s2 10.0.1.2')
    s3.cmd('ifconfig s3 10.0.1.3')
    s4.cmd('ifconfig s4 10.0.1.4')

    #info('*** Enable spanning tree\n')
    #s1.cmd('ovs-vsctl set bridge s1 stp-enable=true')
    #s2.cmd('ovs-vsctl set bridge s2 stp-enable=true')
    #s3.cmd('ovs-vsctl set bridge s3 stp-enable=true')
    #s4.cmd('ovs-vsctl set bridge s4 stp-enable=true')

    info( '*** Running CLI\n' )
    CLI( net )

    info( '*** Stopping network' )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    emptyNet()

