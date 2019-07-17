## IP Prefix Trie
This module is intended for matching IP addresses to arbitrary prefix networks.
This is done using a classic prefix tree (or trie) which stores data at all
nodes within an existing IP network prefix. This module supports both, IPv6 and
legacy IPv4. Separate trees have to be kept for each protocol, of course. See
the following example using an integer, which might represent a customer ID:

```
v6_trie.Insert(123, []string{"2001:db8:1234::/48"})

ip, _, _ := net.ParseCIDR("2001:db8:1234::7/64")
matched_id := v6_trie.Lookup(ip)
```

More examples can be seen in the test cases. This is currently in use to match
Netflow data to customer IDs which are used for billing on a specific upstream
link.


## Internal workings
This module implements a standard trie, which operates on 0 and 1 for
branching. Some care is taken to implement longest prefix matching (i.e.
matching the most specific network) correctly. The Lookup method remembers the
current most specific prefix while descending. The code is thoroughly
commented, go take a look.

Wikipedia has some more [details](https://en.wikipedia.org/wiki/Trie) on tries
in general.


## Benchmark Results
Benchmark results from my Laptop, so you don't have to run them yourself:

```
> go test -bench=. -test.benchtime=10s
goos: linux
goarch: amd64
pkg: ip_prefix_trie
BenchmarkIPv4LookupHit-8            	200000000	        81.1 ns/op
BenchmarkIPv6LookupHit-8            	100000000	       140 ns/op
BenchmarkIPv4LookupProbableMiss-8   	200000000	        65.1 ns/op
BenchmarkIPv6LookupProbableMiss-8   	100000000	       107 ns/op
PASS
ok  	ip_prefix_trie	68.719s
```

In a real environment looking up customer IDs, you can expect lookups within
1us (99th percentile) at about 10k lookups per second using two trees (v6 and
v4) simultaneously. They'll take 600ns on average. Perhaps above benchmark
setup is not very realistic.

## TODO
 * implement payloads as pointer to reduce memory footprint
 * do more realistic benchmarking (and testing)
