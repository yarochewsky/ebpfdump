package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sensor/ebpflib"
	"sensor/memdump"
	"time"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		log.Fatalf("failed to run %v", err)
	}
}

type internalConnectEvent struct {
	Pid  uint32
	Addr uint32
}

type internalTLSEvent struct {
	Src, Dst         uint32
	SrcPort, DstPort uint16
}

func run(ctx context.Context) error {
	coll, err := ebpflib.NewCollection("ebpf_programs/elfs/tls.o")
	if err != nil {
		return err
	}

	events, eventsCloser, err := coll.LoadMap("events")
	if err != nil {
		return err
	}
	defer eventsCloser.Close()

	proxyMap, proxyMapCloser, err := coll.LoadMap("proxy")
	if err != nil {
		return err
	}
	defer proxyMapCloser.Close()

	doneMap, doneMapCloser, err := coll.LoadMap("done")
	if err != nil {
		return err
	}
	defer doneMapCloser.Close()

	rd, rdCloser, err := events.NewReaderFromPerfEventMap()
	if err != nil {
		return err
	}
	defer rdCloser.Close()

	prog, progCloser, err := coll.LoadProgram("xdp_tls_prog")
	if err != nil {
		return err
	}
	defer progCloser.Close()

	progTrace, progTraceCloser, err := coll.LoadProgram("trace_enter_connect")
	if err != nil {
		return err
	}
	defer progTraceCloser.Close()

	tid, err := ebpflib.RegisterTracepoint("sys_enter_connect")
	if err != nil {
		return err
	}

	if err = progTrace.AttachPerfEvent(tid); err != nil {
		return err
	}

	if err = prog.AttachSocketEvent("lo", events); err != nil {
		return err
	}
	defer prog.DetachSocketEvent()

	go proxy()

	openSockets := make(map[uint32]uint32)

	return rd.Read(ctx, func(record ebpflib.Record) error {
		var val uint32

		if err = record.ReadValue(&val); err != nil {
			return err
		}

		if val == 0xdeadbeef {
			var values [][]byte
			if err := proxyMap.Lookup(uint32(0), &values); err != nil {
				return err
			}

			var e internalConnectEvent
			err = binary.Read(bytes.NewBuffer(values[record.CPU()]), binary.LittleEndian, &e)
			if err != nil {
				return fmt.Errorf("error reading buffer %v", err)
			}

			if _, ok := openSockets[e.Addr]; !ok {
				fmt.Println("tracking addr with pid: ", e.Addr, e.Pid)
				openSockets[e.Addr] = e.Pid
			}
		} else {
			var e internalTLSEvent

			if err = record.ReadValue(&e); err != nil {
				return err
			}
			fmt.Println(e)

			pid, ok := openSockets[val]
			if !ok {
				log.Printf("destination address not tracked %v\n", val)
				return nil
			}

			fmt.Println("mem dumping...")
			time.Sleep(5)

			mem, err := memdump.NewMemoryDump(int(pid))
			if err != nil {
				return err
			}
			if err = mem.Dump("p.dump"); err != nil {
				return fmt.Errorf("failed to dump process %d: %v", pid, err)
			}
			delete(openSockets, val)

			var entry uint32
			done := make([]uint8, 4)
			done[record.CPU()] = 1
			time.Sleep(5 * time.Second)
			if err = doneMap.Put(entry, done); err != nil {
				return err
			}
		}

		return nil
	})
}

func proxy() {
	ln, _ := net.Listen("tcp", ":8083")
	conn, err := ln.Accept()
	fmt.Println("accepted")
	if err != nil {
		fmt.Println(err)
		return
	}
	// run loop forever (or until ctrl-c)
	for {
		// will listen for message to process ending in newline (\n)
		message, _ := bufio.NewReader(conn).ReadString('\n')
		// output message received
		fmt.Print("Message Received:", string(message))
	}
}
