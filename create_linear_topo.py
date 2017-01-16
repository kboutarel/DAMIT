#!/usr/bin/env python2
import sys

def write_topo(num_switches):
    with open("topo.txt", "w") as t:
        t.write("switches %d\n" % num_switches)
        t.write("outer_hosts 1\n")
        t.write("inner_hosts 1\n")
        for i in xrange(1, num_switches+1):
            if i == 1:
                t.write("o1 s1\n")
            if i == num_switches:
                t.write("s%s i1\n" % i)
            else:
                t.write("s%s s%s\n" % (i, i+1))


if __name__ == "__main__":
    num_switches = int(sys.argv[1])
    write_topo(num_switches)
