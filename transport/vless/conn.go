package vless

import (
	"encoding/binary"
	"os"
	"strconv"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	N.ExtendedConn
	dst      *DstAddr
	id       uuid.UUID
	addons   *Addons
	x365     bool
	received bool
	sent     bool
}

func (vc *Conn) Read(b []byte) (int, error) {
	if !vc.received {
		if err := vc.recvResponse(); err != nil {
			return 0, err
		}
		vc.received = true
	}
	return vc.ExtendedConn.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if !vc.received {
		if err := vc.recvResponse(); err != nil {
			return err
		}
		vc.received = true
	}
	return vc.ExtendedConn.ReadBuffer(buffer)
}

func (vc *Conn) Write(p []byte) (int, error) {
	if !vc.sent {
		if err := vc.sendRequest(p); err != nil {
			return 0, err
		}
		vc.sent = true
		return len(p), nil
	}

	return vc.ExtendedConn.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if !vc.sent {
		if err := vc.sendRequest(buffer.Bytes()); err != nil {
			return err
		}
		vc.sent = true
		return nil
	}

	return vc.ExtendedConn.WriteBuffer(buffer)
}

func (vc *Conn) sendRequest(p []byte) (err error) {
	var addonsBytes []byte
	if vc.addons != nil {
		addonsBytes, err = proto.Marshal(vc.addons)
		if err != nil {
			return
		}
	}

	requestLen := 1  // protocol version
	requestLen += 16 // UUID
	requestLen += 1  // addons length
	requestLen += len(addonsBytes)
	requestLen += 1 // command
	if !vc.dst.Mux {
		requestLen += 2 // port
		requestLen += 1 // addr type
		requestLen += len(vc.dst.Addr)
	}
	requestLen += len(p)

	buffer := buf.NewSize(requestLen + 3)
	defer buffer.Release()

	if vc.x365 {
		// X365_VARIANT 位开关（临时实验用）: 1=命令字用2 2=端口小端 4=uuid用ASCII
		variant := 0
		if v := os.Getenv("X365_VARIANT"); v != "" {
			if n, e := strconv.Atoi(v); e == nil {
				variant = n
			}
		}
		buf.Must(
			buf.Error(buffer.Write([]byte("X365"))),
			buffer.WriteByte(1),
		)
		cmd := CommandTCP
		if vc.dst.UDP || vc.dst.Mux || variant&1 != 0 {
			cmd = CommandUDP
		}
		buf.Must(buffer.WriteByte(cmd))
		if variant&4 != 0 {
			buf.Must(buf.Error(buffer.WriteString(vc.id.String())))
		} else {
			buf.Must(buf.Error(buffer.Write(vc.id.Bytes())))
		}
		if variant&2 != 0 {
			binary.LittleEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
		} else {
			binary.BigEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
		}
		if !vc.dst.Mux {
			buf.Must(
				buffer.WriteByte(vc.dst.AddrType),
				buf.Error(buffer.Write(vc.dst.Addr)),
			)
		}
		buf.Must(buf.Error(buffer.Write(p)))
		_, err = vc.ExtendedConn.Write(buffer.Bytes())
		return
	}

	buf.Must(
		buffer.WriteByte(Version),              // protocol version
		buf.Error(buffer.Write(vc.id.Bytes())), // 16 bytes of uuid
		buffer.WriteByte(byte(len(addonsBytes))),
		buf.Error(buffer.Write(addonsBytes)),
	)

	if vc.dst.Mux {
		buf.Must(buffer.WriteByte(CommandMux))
	} else {
		if vc.dst.UDP {
			buf.Must(buffer.WriteByte(CommandUDP))
		} else {
			buf.Must(buffer.WriteByte(CommandTCP))
		}

		binary.BigEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
		buf.Must(
			buffer.WriteByte(vc.dst.AddrType),
			buf.Error(buffer.Write(vc.dst.Addr)),
		)
	}

	buf.Must(buf.Error(buffer.Write(p)))

	_, err = vc.ExtendedConn.Write(buffer.Bytes())
	return
}

func (vc *Conn) recvResponse() (err error) {
	if vc.x365 {
		var head [5]byte
		if _, err = io.ReadFull(vc.ExtendedConn, head[:]); err != nil {
			return err
		}
		if string(head[:4]) != "X365" {
			return errors.New("x365: bad magic")
		}
		if head[4] != 0 {
			return fmt.Errorf("x365: server status 0x%02x", head[4])
		}
		return nil
	}
	var buffer [2]byte
	_, err = io.ReadFull(vc.ExtendedConn, buffer[:])
	if err != nil {
		return err
	}

	if buffer[0] != Version {
		return errors.New("unexpected response version")
	}

	length := int64(buffer[1])
	if length != 0 { // addon data length > 0
		io.CopyN(io.Discard, vc.ExtendedConn, length) // just discard
	}

	return
}

func (vc *Conn) Upstream() any {
	return vc.ExtendedConn
}

func (vc *Conn) ReaderReplaceable() bool {
	return vc.received
}

func (vc *Conn) WriterReplaceable() bool {
	return vc.sent
}

func (vc *Conn) NeedHandshake() bool {
	return !vc.sent
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (net.Conn, error) {
	c := &Conn{
		ExtendedConn: N.NewExtendedConn(conn),
		id:           client.uuid,
		addons:       client.Addons,
		dst:          dst,
		x365:         client.X365,
	}

	if client.Addons != nil {
		switch client.Addons.Flow {
		case XRV:
			visionConn, err := vision.NewConn(c, conn, c.id)
			if err != nil {
				return nil, err
			}
			return visionConn, nil
		}
	}

	return c, nil
}
