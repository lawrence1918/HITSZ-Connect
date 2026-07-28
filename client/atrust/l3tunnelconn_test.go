package atrust

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func ipv4Packet(payloadSize int, marker byte) []byte {
	packet := make([]byte, 20+payloadSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[9] = 17
	packet[20] = marker
	return packet
}

func TestReadDataRespPayloadRecognizesLengthFrame(t *testing.T) {
	payload := ipv4Packet(100, 1)
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[2:], payload)

	got, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatalf("read data response: %v", err)
	}
	if mode != "len" || !bytes.Equal(got, payload) {
		t.Fatalf("got mode=%q payload=%d bytes, want length payload=%d bytes", mode, len(got), len(payload))
	}
}

func TestReadDataRespPayloadRecognizesTokenFrame(t *testing.T) {
	packet := ipv4Packet(4, 7)
	token := []byte("token-response-01")
	payload := make([]byte, 0, 1+len(token)+3+2+len(packet))
	payload = append(payload, byte(len(token)))
	payload = append(payload, token...)
	payload = append(payload, 0, 0, 1)
	packetLen := make([]byte, 2)
	binary.BigEndian.PutUint16(packetLen, uint16(len(packet)))
	payload = append(payload, packetLen...)
	payload = append(payload, packet...)

	got, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		t.Fatalf("read data response: %v", err)
	}
	if mode != "token" || !bytes.Equal(got, payload) {
		t.Fatalf("got mode=%q payload=%d bytes, want token payload=%d bytes", mode, len(got), len(payload))
	}
}
