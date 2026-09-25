package wgshim

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	protocolVersion byte = 1
	packetData      byte = 0
	packetProbe     byte = 1
	packetProbeReply byte = 2
	nonceSize            = 12
	headerSize           = 4
	maxInnerPacket       = 65507 - nonceSize - 16 - headerSize
)

var aad = []byte("BPC-WGSHIM-v1")

type Direction int

const (
	ClientToServer Direction = iota
	ServerToClient
)

type Codec struct {
	aead       cipher.AEAD
	paddingMin int
	paddingMax int
	random     io.Reader
}

func LoadPSK(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	text := strings.TrimSpace(string(raw))
	key, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("decode base64 key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}

func DeriveKey(psk []byte, direction Direction) ([]byte, error) {
	if len(psk) != 32 {
		return nil, fmt.Errorf("PSK must be 32 bytes, got %d", len(psk))
	}
	label := "bpc-wgshim-v1-c2s"
	if direction == ServerToClient {
		label = "bpc-wgshim-v1-s2c"
	}
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(label))
	return mac.Sum(nil), nil
}

func NewCodec(key []byte, paddingMin, paddingMax int) (*Codec, error) {
	if paddingMin < 0 || paddingMax < paddingMin || paddingMax > 255 {
		return nil, fmt.Errorf("padding range must satisfy 0 <= min <= max <= 255")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return &Codec{aead: aead, paddingMin: paddingMin, paddingMax: paddingMax, random: rand.Reader}, nil
}

func (c *Codec) Seal(payload []byte) ([]byte, error) {
	return c.sealType(packetData, payload)
}

func (c *Codec) SealProbe(payload []byte) ([]byte, error) {
	return c.sealType(packetProbe, payload)
}

func (c *Codec) SealProbeReply(payload []byte) ([]byte, error) {
	return c.sealType(packetProbeReply, payload)
}

func (c *Codec) sealType(packetType byte, payload []byte) ([]byte, error) {
	if packetType != packetData && packetType != packetProbe && packetType != packetProbeReply {
		return nil, fmt.Errorf("unsupported packet type %d", packetType)
	}
	if len(payload) > maxInnerPacket || len(payload) > 0xffff {
		return nil, fmt.Errorf("inner UDP payload too large: %d", len(payload))
	}
	padLen, err := c.randomPaddingLength()
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, headerSize+len(payload)+padLen)
	plaintext[0] = protocolVersion
	plaintext[1] = packetType
	binary.BigEndian.PutUint16(plaintext[2:4], uint16(len(payload)))
	copy(plaintext[headerSize:], payload)
	if padLen > 0 {
		if _, err := io.ReadFull(c.random, plaintext[headerSize+len(payload):]); err != nil {
			return nil, fmt.Errorf("generate padding: %w", err)
		}
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+c.aead.Overhead())
	out = append(out, nonce...)
	out = c.aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

func (c *Codec) Open(packet []byte) ([]byte, error) {
	packetType, payload, err := c.OpenTyped(packet)
	if err != nil {
		return nil, err
	}
	if packetType != packetData {
		return nil, errors.New("packet is not data")
	}
	return payload, nil
}

func (c *Codec) OpenTyped(packet []byte) (byte, []byte, error) {
	ns := c.aead.NonceSize()
	if len(packet) < ns+c.aead.Overhead()+headerSize {
		return 0, nil, errors.New("outer packet too short")
	}
	nonce := packet[:ns]
	plaintext, err := c.aead.Open(nil, nonce, packet[ns:], aad)
	if err != nil {
		return 0, nil, errors.New("authentication failed")
	}
	if len(plaintext) < headerSize || plaintext[0] != protocolVersion {
		return 0, nil, errors.New("invalid packet header")
	}
	packetType := plaintext[1]
	if packetType != packetData && packetType != packetProbe && packetType != packetProbeReply {
		return 0, nil, errors.New("unsupported packet type")
	}
	payloadLen := int(binary.BigEndian.Uint16(plaintext[2:4]))
	if payloadLen > len(plaintext)-headerSize {
		return 0, nil, errors.New("invalid payload length")
	}
	payload := make([]byte, payloadLen)
	copy(payload, plaintext[headerSize:headerSize+payloadLen])
	return packetType, payload, nil
}

func IsProbe(packetType byte) bool { return packetType == packetProbe }
func IsProbeReply(packetType byte) bool { return packetType == packetProbeReply }
func IsData(packetType byte) bool { return packetType == packetData }

func (c *Codec) randomPaddingLength() (int, error) {
	if c.paddingMin == c.paddingMax {
		return c.paddingMin, nil
	}
	span := c.paddingMax - c.paddingMin + 1
	var b [1]byte
	limit := 256 - (256 % span)
	for {
		if _, err := io.ReadFull(c.random, b[:]); err != nil {
			return 0, fmt.Errorf("generate padding length: %w", err)
		}
		if int(b[0]) < limit {
			return c.paddingMin + int(b[0])%span, nil
		}
	}
}
