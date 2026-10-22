package anytls

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// TestLXPasswordSHA256 校验闪连私有口令变换：
// raw = hex_decode(password); passwordSha256 = raw || (K ^ raw)
func TestLXPasswordSHA256(t *testing.T) {
	const password = "0123456789abcdef0123456789abcdef"
	before := uint64(time.Now().UnixMilli())
	out, ok := lxPasswordSHA256(password)
	after := uint64(time.Now().UnixMilli())
	if !ok {
		t.Fatal("expected 32-char hex password to be accepted")
	}
	raw, err := hex.DecodeString(password)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[:16]) != string(raw) {
		t.Fatalf("first half mismatch: %x", out[:16])
	}
	// 校验第二段落在时间窗口内
	matched := false
	for _, n := range []uint64{before, after, (before + after) / 2} {
		var k [16]byte
		binary.BigEndian.PutUint64(k[0:8], n*10+3)
		binary.BigEndian.PutUint64(k[8:16], n)
		expected := make([]byte, 16)
		for i := 0; i < 16; i++ {
			expected[i] = k[i] ^ raw[i]
		}
		if string(out[16:]) == string(expected) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("second half mismatch: %x", out[16:])
	}
}

func TestLXPasswordRejectsNonHex(t *testing.T) {
	if _, ok := lxPasswordSHA256("short-password"); ok {
		t.Fatal("short password must not be treated as hex")
	}
	if _, ok := lxPasswordSHA256("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); ok {
		t.Fatal("non-hex password must not be treated as hex")
	}
}
