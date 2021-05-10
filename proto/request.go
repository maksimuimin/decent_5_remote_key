package proto

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

const (
	PROTO_REQ_ACTION	uint32 = iota
	PROTO_REQ_CHALLENGE	uint32 = iota
	PROTO_REQ_PROOF		uint32 = iota
)

func RequestTypeString(reqType uint32) string {
	switch reqType {
	case PROTO_REQ_ACTION:
		return "PROTO_REQ_ACTION"
	case PROTO_REQ_CHALLENGE:
		return "PROTO_REQ_CHALLENGE"
	case PROTO_REQ_PROOF:
		return "PROTO_REQ_PROOF"
	default:
		return "UNKNOWN"
	}
}

type Request struct {
	Type uint32
	Challenge uint32
	ChallengeResp uint32
	Signature struct {
		R *big.Int
		S *big.Int
	}
}

func NewSignedRequest(reqType, challengeResp uint32, prvKey *ecdsa.PrivateKey) (*Request, error) {
	var challenge uint32

	switch reqType {
	case PROTO_REQ_ACTION, PROTO_REQ_CHALLENGE:
		r, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}

		challenge = binary.BigEndian.Uint32(r.Bytes())
	case PROTO_REQ_PROOF:
		challenge = 0
	default:
		panic("unknown request type")
	}

	req := Request{
		Type:		reqType,
		Challenge:	challenge,
		ChallengeResp:	challengeResp,
	}

	if err := req.Sign(prvKey); err != nil {
		return nil, fmt.Errorf("req.Sign: %w", err)
	}

	return &req, nil
}

func (req *Request) MD5() ([]byte, error) {
	h := md5.New()

	if err := binary.Write(h, binary.BigEndian, req.Type); err != nil {
		return nil, fmt.Errorf("binary.Write: %w", err)
	}

	if err := binary.Write(h, binary.BigEndian, req.Challenge); err != nil {
		return nil, fmt.Errorf("binary.Write: %w", err)
	}

	if err := binary.Write(h, binary.BigEndian, req.ChallengeResp); err != nil {
		return nil, fmt.Errorf("binary.Write: %w", err)
	}

	return h.Sum(nil), nil
}

func (req *Request) Sign(prvKey *ecdsa.PrivateKey) error {
	h, err := req.MD5()
	if err != nil {
		return fmt.Errorf("req.MD5: %w", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, prvKey, h)
	if err != nil {
		return fmt.Errorf("ecdsa.Sign: %w", err)
	}

	req.Signature.R = r
	req.Signature.S = s

	return nil
}

func (req *Request) Verify(pubKey *ecdsa.PublicKey) (bool, error) {
	h, err := req.MD5()
	if err != nil {
		return false, fmt.Errorf("req.MD5: %w", err)
	}

	return ecdsa.Verify(pubKey, h, req.Signature.R, req.Signature.S), nil
}
