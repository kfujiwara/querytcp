TCP query version of queryperf   querytcp.c
=============================

based on querytcp.c/fujiwara@jprs.co.jp/2009.08.12/version 0.4

Overview
--------

  queryperf for tcp query

  This program measures DNS server performance of TCP query.

Running and development environment:
--------

		FreeBSD: 12.0

		Linux: Debian 9 / 7, Redhat 5

How to make:
--------

    cc -Wall -O2 -g -lm -o querytcp querytcp.c

Options
-------

  querytcp {-d datafile|-r domainname|-V} [-s server_addr] [-p port] [-q num_queries] [-t timeout] [l limit] [-4] [-6] [-h]
  
  -s IPaddr : sets the server to query [127.0.0.1]
  -p port   : sets the port on which to query the server [53]
  -q num    : specifies the maximum number of queries outstanding [120]
  -t timeout: specifies the timeout for query completion in seconds [10]
  -l howlong: specifies how a limit for how long to run tests in seconds
     	      		(no default)
   -e enable EDNS0
   -D set DO bit
   -R set RD bit
   -u Reuse TCP session
  
   Query data (Qname, Qtype) from:
      -d file : input data file / - means from stdin
      -r name : {random}.name A/AAAA queries
      -V      : version.bind CH TXT
  
   -h print this usage

How to use: (Examples)
-----------

  querytcp -V -s 192.168.1.53 -l 60 -t 1 -q 300 -u
  
    queryperf sends "version.bind" CH TXT queries (-V) to
    192.168.1.53:53 (-s and -p 53) for 60 seconds (-l) with timeout 1
    second (-t), 300 tcp connections, reuse TCP connection (-u).
  
  querytcp -r example.com -s ::1 -p 10053 -l 60 -t 1 -q 300
  
    queryperf sends (random).example.com A/AAAA queries to [::1]:10053
    for 60 seconds with timeout 1 second, 300 tcp connections
