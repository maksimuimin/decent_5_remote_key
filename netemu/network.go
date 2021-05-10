// Open network emulator
package netemu

import (
	"context"
	"log"
	"sync"
)

type Addr uint64

const ADDR_BROADCAST Addr = 0

// All sniffers must be read-only, so we use copy of incoming packet
type Sniffer func(p Packet)

type Network struct {
	name string
	addrCntr Addr
	bufSize uint32
	input chan *Packet
	nodes map[Addr] chan *Packet
	wg sync.WaitGroup
	logger *log.Logger
	OnPacketInput Sniffer
}

type Packet struct {
	Sender Addr
	Recipient Addr
	Payload interface{}
}

func NewNetwork(name string, bufSize uint32) *Network {
	return &Network{
		name:		name,
		addrCntr:	ADDR_BROADCAST + 1,
		bufSize:	bufSize,
		input:		make(chan *Packet, bufSize),
		nodes:		make(map[Addr] chan *Packet),
		logger:		log.New(log.Writer(), "netemu.Network: [" + name + "] ",
					log.Flags()),
		OnPacketInput:	nil,
	}
}

func (net *Network) Run() {
	net.wg.Add(1)
	defer net.wg.Done()

	for p := range net.input {
		if net.OnPacketInput != nil {
			net.OnPacketInput(*p)
		}

		if p.Recipient == ADDR_BROADCAST {
			for _, output := range net.nodes {
				output<- p
			}
			continue
		}

		output, ok := net.nodes[p.Recipient]
		if !ok {
			net.logger.Printf("attempt to send packet for unknown recipient: " +
			"(%d) -> (%d) %s\n", p.Sender, p.Recipient, p.Payload)
		}

		output<- p
	}
}

func (net *Network) Close() {
	close(net.input)
	net.wg.Wait()

	for _, output := range net.nodes {
		close(output)
	}
}

type NetworkHandle struct {
	addr Addr
	input chan<- *Packet
	output <-chan *Packet
}

func (net *Network) Join() *NetworkHandle {
	addr := net.addrCntr
	net.addrCntr++

	output := make(chan *Packet, net.bufSize)
	net.nodes[addr] = output

	return &NetworkHandle{
		addr:	addr,
		input:	net.input,
		output:	output,
	}
}

func (nh *NetworkHandle) Addr() Addr {
	return nh.addr
}

func (nh *NetworkHandle) Send(ctx context.Context, p *Packet) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case nh.input<- p:
		return nil
	}
}

func (nh *NetworkHandle) Recieve(ctx context.Context) (*Packet, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case p := <-nh.output:
		return p, nil
	}
}
