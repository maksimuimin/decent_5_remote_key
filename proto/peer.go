package proto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/DragonF0rm/decent_5_remote_key/netemu"
)

var ErrChallengeFailed = errors.New("challenge failed")

type Peer struct {
	name string
	pubKey *ecdsa.PublicKey
	prvKey *ecdsa.PrivateKey
	// Assume that both car and key know each other public keys
	targetPubKey *ecdsa.PublicKey
	nh *netemu.NetworkHandle
	logger *log.Logger
}

func NewPeer(name string, net *netemu.Network) (*Peer, error) {
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}

	return &Peer{
		name:	name,
		pubKey:	&prvKey.PublicKey,
		prvKey:	prvKey,
		nh:	net.Join(),
		logger:	log.New(log.Writer(), "proto.Peer: [" + name + "] ", log.Flags()),
	}, nil
}

func (peer *Peer) PubKey() *ecdsa.PublicKey {
	return peer.pubKey
}

func (peer *Peer) Addr() netemu.Addr {
	return peer.nh.Addr()
}

func (peer *Peer) SetTargetPubKey(targetPubKey *ecdsa.PublicKey) {
	peer.targetPubKey = targetPubKey
}

func (peer *Peer) Send(ctx context.Context, req *Request) error {
	if err := peer.nh.Send(ctx, &netemu.Packet{
		Sender:		peer.nh.Addr(),
		Recipient:	netemu.ADDR_BROADCAST,
		Payload:	req,
	}); err != nil {
		return fmt.Errorf("peer.nh.Send: %w", err)
	}

	return nil
}

func (peer *Peer) RecieveVerified(ctx context.Context, reqType uint32) (*Request, error) {
	for {
		p, err := peer.nh.Recieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("peer.nh.Recieve: %w", err)
		}

		r, ok := p.Payload.(*Request)
		if !ok {
			peer.logger.Printf("got packet with invalid payload, dropping: %v\n", p)
			continue
		}

		if r.Type != reqType {
			peer.logger.Printf("got packet with unexpected request type, dropping: %v\n", p)
			continue
		}

		ok, err = r.Verify(peer.targetPubKey)
		if err != nil {
			return nil, fmt.Errorf("r.Verify: %w", err)
		}

		if !ok {
			peer.logger.Printf("request verification failed, dropping: %v\n", r)
			continue
		}

		return r, nil
	}
}

func (peer *Peer) ExecAction(ctx context.Context) error {
	reqAction, err := NewSignedRequest(PROTO_REQ_ACTION, 0, peer.prvKey)
	if err != nil {
		return fmt.Errorf("NewSignedRequest: %w", err)
	}

	if err = peer.Send(ctx, reqAction); err != nil {
		return fmt.Errorf("peer.Send: %w", err)
	}

	reqChallenge, err := peer.RecieveVerified(ctx, PROTO_REQ_CHALLENGE)
	if err != nil {
		return fmt.Errorf("peer.RecieveVerified: %w", err)
	}

	if reqAction.Challenge != reqChallenge.ChallengeResp {
		return fmt.Errorf("%w: expected %d, got %d", ErrChallengeFailed,
				  reqAction.Challenge, reqChallenge.ChallengeResp)
	}

	reqProof, err := NewSignedRequest(PROTO_REQ_PROOF, reqChallenge.Challenge, peer.prvKey)
	if err != nil {
		return fmt.Errorf("NewSignedRequest: %w", err)
	}

	if err = peer.Send(ctx, reqProof); err != nil {
		return fmt.Errorf("peer.Send: %w", err)
	}

	return nil
}

func (peer *Peer) HandleAction(ctx context.Context) error {
	reqAction, err := peer.RecieveVerified(ctx, PROTO_REQ_ACTION)
	if err != nil {
		return fmt.Errorf("peer.RecieveVerified: %w", err)
	}

	reqChallenge, err := NewSignedRequest(PROTO_REQ_CHALLENGE, reqAction.Challenge, peer.prvKey)
	if err != nil {
		return fmt.Errorf("NewSignedRequest: %w", err)
	}

	if err = peer.Send(ctx, reqChallenge); err != nil {
		return fmt.Errorf("peer.Send: %w", err)
	}

	reqProof, err := peer.RecieveVerified(ctx, PROTO_REQ_PROOF)
	if err != nil {
		return fmt.Errorf("peer.RecieveVerified: %w", err)
	}

	if reqChallenge.Challenge != reqProof.ChallengeResp {
		return fmt.Errorf("%w: expected %d, got %d", ErrChallengeFailed,
				  reqChallenge.Challenge, reqProof.ChallengeResp)
	}

	peer.logger.Println("ACTION EXECUTED")

	return nil
}
