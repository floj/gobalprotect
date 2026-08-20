package gpst

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// GPST SSL tunnel packet header format:
//
//	0x00-0x03: Magic "\x1a\x2b\x3c\x4d"
//	0x04-0x05: Big-endian EtherType (0x0800=IPv4, 0x86DD=IPv6, 0x0000=keepalive)
//	0x06-0x07: Big-endian 16-bit payload length (not including 16-byte header)
//	0x08-0x0F: "\x01\x00\x00\x00\x00\x00\x00\x00" for data, all zeros for keepalive
//	0x10+:     data payload

const (
	HeaderSize = 16
	Magic      = 0x1a2b3c4d

	EtherTypeIPv4      = 0x0800
	EtherTypeIPv6      = 0x86DD
	EtherTypeKeepalive = 0x0000
)

var (
	ErrBadMagic    = errors.New("gpst: bad magic in packet header")
	ErrShortPacket = errors.New("gpst: short packet")
)

// Header represents a GPST packet header.
type Header struct {
	Magic     uint32
	EtherType uint16
	Length    uint16
	Flags     uint32
	Reserved  uint32
}

// EncodePacket wraps a payload in a GPST packet header.
func EncodePacket(payload []byte) []byte {
	etherType := uint16(EtherTypeIPv4)
	if len(payload) > 0 && (payload[0]>>4) == 6 {
		etherType = EtherTypeIPv6
	}

	pkt := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(pkt[0:4], Magic)
	binary.BigEndian.PutUint16(pkt[4:6], etherType)
	binary.BigEndian.PutUint16(pkt[6:8], uint16(len(payload)))
	binary.LittleEndian.PutUint32(pkt[8:12], 1) // flags
	binary.LittleEndian.PutUint32(pkt[12:16], 0)
	copy(pkt[HeaderSize:], payload)
	return pkt
}

// EncodeKeepalive creates a keepalive/DPD packet.
func EncodeKeepalive() []byte {
	pkt := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(pkt[0:4], Magic)
	// EtherType, length, flags, reserved all zero
	return pkt
}

// ReadPacket reads a full GPST packet from the reader.
// Returns the ethertype and payload.
func ReadPacket(r io.Reader) (etherType uint16, payload []byte, err error) {
	hdr := make([]byte, HeaderSize)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, fmt.Errorf("gpst: reading header: %w", err)
	}

	magic := binary.BigEndian.Uint32(hdr[0:4])
	if magic != Magic {
		return 0, nil, ErrBadMagic
	}

	etherType = binary.BigEndian.Uint16(hdr[4:6])
	length := binary.BigEndian.Uint16(hdr[6:8])

	if length == 0 {
		return etherType, nil, nil
	}

	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("gpst: reading payload: %w", err)
	}
	return etherType, payload, nil
}
