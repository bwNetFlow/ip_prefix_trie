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
		t.Logf(" OK: IP '%s' matched KNR '123'", ip)
	}
}

func TestLookupIPv6(t *testing.T) {
	ip, _, _ := net.ParseCIDR("2001:db8:1234::7/64")
	matched_knr := v6_trie.Lookup(ip)
	if matched_knr == nil || 123 != matched_knr.(int) {
		t.Errorf("ERR: IP '%s' should match '123', was '%v'", ip, matched_knr)
	} else {
		t.Logf(" OK: IP '%s' matched KNR '123'", ip)
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
