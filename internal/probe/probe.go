package probe

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -cc clang probe probe.c -- -Wall -I../../include

type flow struct {
	synLabel uint32
	ackLabel uint32
	lAddr    netaddr.IP
	rAddr    netaddr.IP
	lPort    uint16
	rPort    uint16
}

func Run(ctx context.Context) error {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		return err
	}

	var probe probeObjects
	if err := loadProbeObjects(&probe, nil); err != nil {
		return err
	}

	kp, err := link.Kprobe("tcp_set_state", probe.KprobeTcpSetState)
	if err != nil {
		return err
	}
	defer kp.Close()

	pipe := probe.Pipe
	rd, err := perf.NewReader(pipe, 10)
	if err != nil {
		return err
	}
	defer rd.Close()

	c := make(chan []byte)
	go func() {
		for {
			event, err := rd.Read()
			if err != nil {
				fmt.Println(err)
				continue
			}
			c <- event.RawSample
		}
	}()

	for {
		select {
		case <-ctx.Done():
			kp.Close()
			return probe.Close()
		case raw := <-c:
			var lAddr, rAddr [16]byte
			copy(lAddr[:], raw[8:24])
			copy(rAddr[:], raw[24:40])

			flow := flow{
				synLabel: binary.BigEndian.Uint32(raw[0:4]),
				ackLabel: binary.BigEndian.Uint32(raw[4:8]),
				lAddr:    netaddr.IPFrom16(lAddr),
				rAddr:    netaddr.IPFrom16(rAddr),
				lPort:    binary.LittleEndian.Uint16(raw[40:42]), // this is little endian for some reason
				rPort:    binary.BigEndian.Uint16(raw[42:44]),
			}
			fmt.Printf("src: %v : %d\n", flow.rAddr.String(), flow.rPort)
			fmt.Printf("dest: %v : %d\n", flow.lAddr.String(), flow.lPort)
			fmt.Printf("flow label modified: %v\n", flow.synLabel != flow.ackLabel)
			fmt.Printf("\n")
		}
	}
}
