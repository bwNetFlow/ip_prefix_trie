
## Benchmark Results

```
> go test -bench=. -test.benchtime=10s
goos: linux
goarch: amd64
pkg: ip_prefix_trie
BenchmarkIPv4LookupHit-8            	200000000	        81.1 ns/op
BenchmarkIPv6LookupHit-8            	100000000	       140 ns/op
BenchmarkIPv4LookupPropableMiss-8   	200000000	        65.1 ns/op
BenchmarkIPv6LookupPropableMiss-8   	100000000	       107 ns/op
PASS
ok  	ip_prefix_trie	68.719s
```
