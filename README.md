# P4 TCP retransmission tracker

This sample P4 application tracks TCP retransmission by looking for TCP SEQ numbers and saving flow information if a particular SYN number is repeated for a given flow.

### Run it

You will need to install `bmv2` and `bmv2-ss`. Then you can compile everything, create a mininet topology and run the software switches with:

    ./run_demo.sh

You can generate retransmissions jsut by starting an iperf client (since the flow entries are deliberately wrong in the switch, the connection won't build up which means iperf keeps retransmitting the same packet).

    mininet> h1 iperf -c 10.0.2.10

### controller.py

You can read out the flows that have been saved at the device experiencing TCP retransmissions:

    $ python controller.py read
    Flows that are experiencing TCP transmissions:
    Hash    Source IP    Port   Dest. IP    Port    Retransmissions
    11      10.0.1.10    45752  10.0.2.10   5001    2 
