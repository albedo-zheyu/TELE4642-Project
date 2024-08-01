#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, UserSwitch, OVSKernelSwitch
from mininet.link import Link
from mininet.cli import CLI
from mininet.log import setLogLevel

'''
Overview of the Topology
    Controller: 1 Remote Controller
    Switches: 2 (s1, s2)
    Hosts: 6 (h1, h2, h3, h4, h5, h6)
    Links:
        Switch s1 connected to hosts h1, h2, h3
        Switch s2 connected to hosts h4, h5, h6
        Link between switch s1 and switch s2
Topolpgy diagram
           +-------+
           |  c0   |
           +-------+
               |
      -----------------
      |               |
  +-------+       +-------+
  |   s1  |-------|   s2  |
  +-------+       +-------+
  /   |   \       /   |   \
h1   h2   h3     h4   h5   h6
'''
def topology():
    # 创建一个Mininet网络对象，并设置
    #   build为False表示稍后手动构建网络，
    #   controller设置为None表示暂时不添加控制器，
    #   autoSetMacs为True表示自动设置MAC地址。
    print '*** Creating network'
    net = Mininet(build=False, controller=None, autoSetMacs = True)

    # 添加一个远程控制器，名称为c0，IP地址为127.0.0.1，端口为6633。
    print '*** Adding controller'
    c0 = net.addController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6633 )

    # 添加两个交换机，s1是一个OVS内核交换机，s2是一个用户交换机。它们使用OpenFlow13协议，监听端口分别为6673和6674。
    print '*** Adding switches'
    s1 = net.addSwitch( 's1', listenPort=6673, protocols='OpenFlow13', cls=OVSKernelSwitch, failMode='standalone' )
    s2 = net.addSwitch( 's2', listenPort=6674, protocols='OpenFlow13', cls=UserSwitch )
    # 输出所有交换机的名称。
    # Print the name of all switches.
    for s in net.switches:
        print('%s ' % s.name),
    print " "

    # There are 6 hosts in the network. hosts1 includes h1, h2, h3. hosts2 includes h4, h5, h6
    # 添加6个主机，hosts1包含主机h1, h2, h3，hosts2包含主机h4, h5, h6。
    print '*** Adding hosts'
    hosts1 = [ net.addHost( 'h%d' % n ) for n in xrange(1,4) ]
    hosts2 = [ net.addHost( 'h%d' % n ) for n in xrange(4,7) ]
    # 输出所有主机的名称。
    for h in net.hosts:
        print('%s ' % h.name),
    print " "

    # 为每个主机和对应的交换机添加链路，并添加一个交换机之间的链路。
    print '*** Adding links'
    for h in hosts1:
        net.addLink( s1, h )
        print ('(%s, %s) ' % (s1.name, h.name)),
    for h in hosts2:
        net.addLink( s2, h )
        print ('(%s, %s) ' % (s2.name, h.name)),
    net.addLink( s1, s2 )
    print ('(%s, %s) ' % (s1.name, s2.name)),
    print " "

    # 构建网络，启动交换机1和交换机2，其中c0控制交换机2。
    print '*** Starting network'
    net.build()
    s1.start( [] )
    s2.start( [c0] )

    # 配置主机 Configuring hosts
    # print '*** Configuring hosts'
    for h in net.hosts:
        h.cmd('sudo ethtool -K %s-eth0 tso off' % h.name )

    # print '*** Running CLI'
    CLI( net )

    print '*** Stopping network'
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
