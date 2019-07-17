package ip_prefix_trie

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

var v4_trie, v6_trie TrieNode

func TestInsert(t *testing.T) {
	v4_trie.Insert(123, []string{"192.168.0.0/16"})
	v6_trie.Insert(123, []string{"2001:db8:1234::/48"})
}

func TestLookupIPv4(t *testing.T) {
	ip, _, _ := net.ParseCIDR("192.168.0.7/24")
	matched_knr := v4_trie.Lookup(ip)
	if matched_knr == nil || 123 != matched_knr.(int) {
		t.Errorf("ERR: IP '%s' should match '123', was '%v'", ip, matched_knr)
	} else {
		t.Logf(" OK: IP '%s' matched Cid '123'", ip)
	}
}

func TestLookupIPv6(t *testing.T) {
	ip, _, _ := net.ParseCIDR("2001:db8:1234::7/64")
	matched_knr := v6_trie.Lookup(ip)
	if matched_knr == nil || 123 != matched_knr.(int) {
		t.Errorf("ERR: IP '%s' should match '123', was '%v'", ip, matched_knr)
	} else {
		t.Logf(" OK: IP '%s' matched Cid '123'", ip)
	}
}

func TestSubTrieCorrectness(t *testing.T) {
	var my_trie TrieNode
	my_trie.Insert(1, []string{"0.0.0.0/0"})
	my_trie.Insert(3, []string{"255.255.255.255/32"})
	my_trie.Insert(2, []string{"255.255.0.0/16"})
	my_trie.Print("", true)
	ip1, _, _ := net.ParseCIDR("0.0.0.1/32")
	ip2, _, _ := net.ParseCIDR("255.255.0.1/32")
	ip3, _, _ := net.ParseCIDR("255.255.255.255/32")
	matched_knr1 := my_trie.Lookup(ip1)
	if matched_knr1 == nil || 1 != matched_knr1.(int) {
		t.Errorf("ERR: IP '%s' should match '1', was '%v'", ip1, matched_knr1)
	} else {
		t.Logf(" OK: IP '%s' matched Cid '1'", ip1)
	}
	matched_knr2 := my_trie.Lookup(ip2)
	if matched_knr2 == nil || 2 != matched_knr2.(int) {
		t.Errorf("ERR: IP '%s' should match '2', was '%v'", ip2, matched_knr2)
	} else {
		t.Logf(" OK: IP '%s' matched Cid '2'", ip2)
	}
	matched_knr3 := my_trie.Lookup(ip3)
	if matched_knr3 == nil || 3 != matched_knr3.(int) {
		t.Errorf("ERR: IP '%s' should match '3', was '%v'", ip3, matched_knr3)
	} else {
		t.Logf(" OK: IP '%s' matched Cid '3'", ip3)
	}
}

func TestUint128Shift(t *testing.T) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	var myUint Uint128 = Uint128{r1.Uint64(), r1.Uint64()}
	var myShiftedUint Uint128 = myUint.ShiftRight(1)

	str1 := fmt.Sprintf("%064b%064b\n", myUint.H, myUint.L)
	str2 := fmt.Sprintf("%064b%064b\n", myShiftedUint.H, myShiftedUint.L)

	if str1[0:127] != str2[1:128] {
		t.Errorf("Incorrect ShiftRight result for %d.\n", myUint)
		t.Log(str1)
		t.Log(str2)
	}
}

func TestUint128ShiftLong(t *testing.T) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	var myUint Uint128 = Uint128{r1.Uint64(), r1.Uint64()}
	var myShiftedUint Uint128 = myUint.ShiftRight(100)

	str1 := fmt.Sprintf("%064b%064b\n", myUint.H, myUint.L)
	str2 := fmt.Sprintf("%064b%064b\n", myShiftedUint.H, myShiftedUint.L)

	if str1[0:28] != str2[100:128] {
		t.Errorf("Incorrect ShiftRight result for %d.\n", myUint)
		t.Log(str1)
		t.Log(str2)
	}
}

func BenchmarkIPv4LookupHit(b *testing.B) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	for n := 0; n < b.N; n++ {
		ip := net.IPv4(192, 168, byte(r1.Int()), byte(r1.Int()))
		v4_trie.Lookup(ip)
	}
}

func BenchmarkIPv6LookupHit(b *testing.B) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	for n := 0; n < b.N; n++ {
		ip_data := make([]byte, 16)
		binary.LittleEndian.PutUint64(ip_data, r1.Uint64())
		ip_data[0] = 0x20
		ip_data[1] = 0x01
		ip_data[2] = 0x0d
		ip_data[3] = 0xb8
		ip_data[4] = 0x12
		ip_data[5] = 0x34
		ip := net.IP(ip_data)
		v6_trie.Lookup(ip)
	}
}

func BenchmarkIPv4LookupPropableMiss(b *testing.B) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	for n := 0; n < b.N; n++ {
		ip := net.IPv4(byte(r1.Int()), byte(r1.Int()), byte(r1.Int()), byte(r1.Int()))
		v4_trie.Lookup(ip)
	}
}

func BenchmarkIPv6LookupPropableMiss(b *testing.B) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	for n := 0; n < b.N; n++ {
		ip_data := make([]byte, 16)
		binary.LittleEndian.PutUint64(ip_data, r1.Uint64())
		ip_data[0] = 0x20
		ip_data[1] = 0x01
		ip_data[2] = 0x0d
		ip_data[3] = 0xb8
		ip := net.IP(ip_data)
		v6_trie.Lookup(ip)
	}
}
