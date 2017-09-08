'''
Python controller that reads register values from a P4 switch.
'''

import os
import subprocess
import argparse


def inttoip(ipnum):
    ipnum = int(ipnum)
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

def read_register(register, idx):
    p = subprocess.Popen('simple_switch_CLI', stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    stdout, stderr = p.communicate(input="register_read %s %d" % (register, idx))
    reg_val = filter(lambda l: ' %s[%d]' % (register, idx) in l, stdout.split('\n'))[0].split('= ', 1)[1]
    return reg_val

def reset_register(register):
    p = subprocess.Popen('simple_switch_CLI', stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    p.communicate(input="register_reset %s" % register)

def print_results(flows):
    print 'Flows that are experiencing TCP transmissions:'
    print 'Hash \tSource IP \t Port \tDest. IP \tPort \tRetransmissions'
    for k, v in flows.iteritems():
        print "%d \t%s \t%s \t%s \t%s \t%s" % ( k,
            inttoip(v['source_ip']), 
            v['source_port'], 
            inttoip(v['destination_ip']), 
            v['destination_port'], 
            v['rt_counter'])


def read_retransmissions():
    flow_counter = int(read_register('flow_counter_register', 0))
    flows = {}
    for i in range(1, flow_counter):
        flow = {}
        flow_hash = int(read_register('flow_hash_register', i))
        flow['source_ip'] = read_register('flow_source_register', flow_hash)
        flow['source_port'] = read_register('flow_sourceport_register', flow_hash)
        flow['destination_ip'] = read_register('flow_destination_register', flow_hash)
        flow['destination_port'] = read_register('flow_destinationport_register', flow_hash)
        flow['rt_counter'] = read_register('flow_rtcounter_register', flow_hash)
        flows[flow_hash] = flow 
    
    print_results(flows)
    

def reset_counters():
    for i in ['flow_hash_register', 'flow_source_register', 
            'flow_sourceport_register', 'flow_destination_register', 
            'flow_destinationport_register', 'flow_rtcounter_register',
            'flow_counter_register']:
        reset_register(i)

def main():
    parser = argparse.ArgumentParser(description='Control the switch collecting retransmissions per flow.')
    parser.add_argument('command')
    args = parser.parse_args()
    command = args.command

    if command == "read":
        read_retransmissions()
    elif command == "reset":
        reset_counters()
    else:
        print 'wrong command. try: read or reset'

if __name__ == "__main__":
    main()

