package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/DragonF0rm/decent_5_remote_key/netemu"
	"github.com/DragonF0rm/decent_5_remote_key/proto"
)

func GetSniffer(carAddr, keyAddr netemu.Addr) netemu.Sniffer {
	return func (p netemu.Packet) {
		var prefix string

		switch p.Sender {
		case carAddr:
			prefix = "(KEY) <- (CAR)"
		case keyAddr:
			prefix = "(KEY) -> (CAR)"
		}

		req, ok := p.Payload.(*proto.Request)
		if !ok {
			log.Println(p)
			return
		}

		log.Printf("%s [%s] challenge: %d, challengeResp: %d, signature: {r: %v, s: %v)",
			   prefix, proto.RequestTypeString(req.Type), req.Challenge,
			   req.ChallengeResp, req.Signature.R, req.Signature.S)
		return
	}
}

func main() {
	net := netemu.NewNetwork("RADIO", 10)
	defer net.Close()

	car, err := proto.NewPeer("CAR", net)
	if err != nil {
		log.Fatalln(err)
	}

	key, err := proto.NewPeer("KEY", net)
	if err != nil {
		log.Fatalln(err)
	}

	car.SetTargetPubKey(key.PubKey())
	key.SetTargetPubKey(car.PubKey())

	net.OnPacketInput = GetSniffer(car.Addr(), key.Addr())

	go net.Run()

	var wg sync.WaitGroup
	wg.Add(2)

	go func () {
		ctx, cancel := context.WithTimeout(context.Background(), 1 * time.Second)
		defer cancel()

		err := car.HandleAction(ctx)
		if err != nil {
			log.Printf("car.HandleAction: %v\n", err)
		}

		wg.Done()
	}()

	go func () {
		ctx, cancel := context.WithTimeout(context.Background(), 1 * time.Second)
		defer cancel()

		err := key.ExecAction(ctx)
		if err != nil {
			log.Printf("key.ExecAction: %v\n", err)
		}

		wg.Done()
	}()

	wg.Wait()
}
