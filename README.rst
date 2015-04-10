SDN Hands-On Tutorial
=====================

This tutorial based on the Ryu SDN controller was given at the [COST ACROSS Summer School 2015](http://summerschool2015.informatik.uni-wuerzburg.de) at the [University of Würzburg, Germany](http://www3.informatik.uni-wuerzburg.de).

The tutorial included implementation of two controller apps:

- [ryu.app.learningswitch](https://github.com/StephenKing/summerschool-2015-ryu/blob/summerschool/ryu/app/learningswitch.py): A simple Layer 2 switch implementation.
- [ryu.app.shortestpath](https://github.com/StephenKing/summerschool-2015-ryu/blob/summerschool/ryu/app/shortestpath.py) a more sophisticated implementation using [networkx](https://networkx.github.io) to compute shortest path also through a topology consisting of loops.

The virtual machine used in the tutorial (based on the work of [SDN Hub](http://sdnhub.org/tutorials/sdn-tutorial-vm/)) can be downloaded [here](http://www3.informatik.uni-wuerzburg.de/staff/steffen.gebert/download/SDN-Hands-On_Summerschool_2015.ova).

The scripts `./run_mininet1.sh` (1 switch for the learning switch scenario)and `./run_mininet4.py` (4 meshed switches for the shortest path scenario) can be used to connect hosts and switches to the controller.

What's Ryu
==========
Ryu is a component-based software defined networking framework.

Ryu provides software components with well defined API that make it
easy for developers to create new network management and control
applications. Ryu supports various protocols for managing network
devices, such as OpenFlow, Netconf, OF-config, etc. About OpenFlow,
Ryu supports fully 1.0, 1.2, 1.3, 1.4 and Nicira Extensions.

All of the code is freely available under the Apache 2.0 license. Ryu
is fully written in Python.


Quick Start
===========
Installing Ryu is quite easy::

   % pip install ryu

If you prefer to install Ryu from the source code::

   % git clone git://github.com/osrg/ryu.git
   % cd ryu; python ./setup.py install

If you want to use Ryu with `OpenStack <http://openstack.org/>`_,
please refer `networking-ofagent project <https://github.com/stackforge/networking-ofagent>`_.

If you want to write your Ryu application, have a look at
`Writing ryu application <http://ryu.readthedocs.org/en/latest/writing_ryu_app.html>`_ document.
After writing your application, just type::

   % ryu-manager yourapp.py


Optional Requirements
=====================

Some functionalities of ryu requires extra packages:

- OF-Config requires lxml
- NETCONF requires paramiko
- BGP speaker (net_cntl) requires paramiko

If you want to use the functionalities, please install requirements::

    % pip install lxml
    % pip install paramiko


Support
=======
Ryu Official site is `<http://osrg.github.io/ryu/>`_.

If you have any
questions, suggestions, and patches, the mailing list is available at
`ryu-devel ML
<https://lists.sourceforge.net/lists/listinfo/ryu-devel>`_.
`The ML archive at Gmane <http://dir.gmane.org/gmane.network.ryu.devel>`_
is also available.
