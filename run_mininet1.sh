#!/bin/bash
sudo mn --topo single,3 --mac --controller remote --switch ovsk
sudo ovs-vsctl set bridge s1 protocols=OpenFlow13

