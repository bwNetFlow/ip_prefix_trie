package ip_prefix_trie

import (
	"encoding/binary"
	"fmt"
	"net"
)

type TrieNode struct {
	LNode, RNode *TrieNode
	Payload      interface{}
}

// very large uint, needed for IPv6
type Uint128 struct {
	H, L uint64
}

// shift right by n, used to extract single bits
func (u Uint128) ShiftRight(n uint) Uint128 {
	newH := u.H >> n
	newL := u.L >> n
	if n <= 64 {
		newL |= u.H << (64 - n)
	} else {
		newL = u.H >> (n - 64)
	}
	return Uint128{newH, newL}
}

// used to fill our custom type, basically the same as FromBytes
func ip2int(ip net.IP) Uint128 {
	hi := binary.BigEndian.Uint64(ip.To16()[:8])
	lo := binary.BigEndian.Uint64(ip.To16()[8:])
	return Uint128{hi, lo}
}

// Insert data for a number of prefixes below a given root node
//
// Parameters:
//	- trie is a (root) TrieNode
//	- payload is the data stored for a prefix
//	- prefixes is a slice of prefixes
func (t *TrieNode) Insert(payload interface{}, prefixes []string) {
	for _, cidr := range prefixes {
		ip, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Printf("Error parsing prefix: %v\n", err)
		}
		plen, max_plen := prefix.Mask.Size()
		var bits Uint128 = ip2int(ip)
		for i := 0; i <= plen; i++ {
			next_bit := bits.ShiftRight(uint(max_plen-i)).L & 1
			var next_node **TrieNode
			if next_bit == 0 {
				next_node = &t.LNode
			} else if next_bit == 1 {
				next_node = &t.RNode
			}
			if *next_node == nil {
				*next_node = new(TrieNode)
				(*next_node).Payload = t.Payload
			}
			t = *next_node
		}
		t.Payload = payload        // needed, might be set by less specific
		t.set_for_subtrie(payload) // overwrites all empty nodes below this
	}
}

// Finish an insertion by writing the content data recursively.
// An example why this is necessary:
//	1. Prefix A is contained in prefix B, i.e. A is more specific than B
//	2. A was added before B
//	3. B needs to match more specific prefixes which are not in A
//	4. TrieNodes below B exist as a connection to A, and may be
//	   uninitialised if the differnce between both prefix lengths is > 1
//	5. If such empty TrieNodes exist, they need to be updated to B's
//	   content
func (node *TrieNode) set_for_subtrie(payload interface{}) {
	if node != nil {
		// this check prevents more specific prefixes which already
		// exist in the trie from being overwritten, if they're
		// initialised
		// Second branch in OR is needed to call recursively.
		if node.Payload == nil || node.Payload == payload {
			node.Payload = payload
			node.LNode.set_for_subtrie(payload)
			node.RNode.set_for_subtrie(payload)
		}
	}
}

// Match an IP to the prefixes and return the correct content.
// Selects IPv4 or IPv6 mode, i.e. the correct prefix length, automatically.
func (t *TrieNode) Lookup(ip net.IP) interface{} {
	// Find maximum prefix length depending on query.
	// Mind that the query has to match the Trie's IP version, else the
	// results will be nonsense.
	var max_plen int
	if ip.To4() == nil {
		max_plen = 128
	} else {
		max_plen = 32
	}

	var bits Uint128 = ip2int(ip)
	for i := uint(max_plen); i > 0; i-- {
		next_bit := bits.ShiftRight(i).L & 1
		if next_bit == 0 && t.LNode != nil {
			t = t.LNode
		} else if next_bit == 1 && t.RNode != nil {
			t = t.RNode
		} else {
			break
		}
	}
	return t.Payload
}
