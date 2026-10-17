# Offline visibility; this script observes an existing capture, never creates traffic.
@load base/protocols/dns
@load base/protocols/http

event zeek_init()
    {
    print "network-lab: synthetic offline PCAP; inspect dns.log, http.log and conn.log";
    }
