package anytls

// LightXtreme / 闪连 私有 anytls 口令变换。
//
//	raw = hex_decode(password)          // 配置中 32 字符 hex -> 16 字节
//	n   = 当前 unix 毫秒
//	K   = u64be(n*10 + 3) || u64be(n)   // 两档时间戳
//	passwordSha256 = raw || (K ^ raw)   // 32 字节
//
// 上游 anytls 发送的是 sha256(password_string)，服务端 0.1s 内关闭连接；
// 私有内核发送上面这个时间掩码后的 32 字节，服务端才放行。

import (
	"encoding/binary"
	"encoding/hex"
	"time"
)

func lxPasswordSHA256(password string) ([32]byte, bool) {
	var out [32]byte
	if len(password) != 32 {
		return out, false
	}
	raw, err := hex.DecodeString(password)
	if err != nil || len(raw) != 16 {
		return out, false
	}
	n := uint64(time.Now().UnixMilli())
	var k [16]byte
	binary.BigEndian.PutUint64(k[0:8], n*10+3)
	binary.BigEndian.PutUint64(k[8:16], n)
	copy(out[:16], raw)
	for i := 0; i < 16; i++ {
		out[16+i] = k[i] ^ raw[i]
	}
	return out, true
}
