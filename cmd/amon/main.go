package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	utils "github.com/Dishank-Sen/Amon"
	"github.com/Dishank-Sen/Amon/internal/paths"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
)

type Event struct {
	Pid      uint32
	Tgid     uint32
	Comm     [16]byte
	Filename [256]byte
}

type Objs struct {
    AllowedCommands *ebpf.Map     `ebpf:"allowed_commands"`
    TraceOpenat    *ebpf.Program `ebpf:"trace_openat"`
    TraceOpenatExit    *ebpf.Program `ebpf:"trace_openat_exit"`
	Events     *ebpf.Map     `ebpf:"events"`
}

func main(){
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	collPath := filepath.Join("internal", "bpf", "trace.o")
	spec, err := ebpf.LoadCollectionSpec(collPath)
	if err != nil{
		panic(err)
	}

	var objs Objs
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.AllowedCommands.Close()
	defer objs.TraceOpenat.Close()
	defer objs.TraceOpenatExit.Close()

	cfg, err := utils.Load(paths.ConfigFile())
	if err != nil {
		panic(err)
	}
	// fmt.Println(cfg.TrackedCommands)

	for _, v := range cfg.TrackedCommands{
		var key [16]byte
		copy(key[:], v)
	
		var value uint8 = 1
	
		if err := objs.AllowedCommands.Put(key, value); err != nil{
			panic(err)
		}
	}

	tpOpen, err := link.Tracepoint(
		"syscalls",
		"sys_enter_openat",
		objs.TraceOpenat,
		nil,
	)
	if err != nil {
		panic(err)
	}
	defer tpOpen.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Listening for events...")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}

				fmt.Println("ringbuf read:", err)
				return
			}

			var event Event

			if err := binary.Read(
				bytes.NewBuffer(record.RawSample),
				binary.LittleEndian,
				&event,
			); err != nil {
				continue
			}

			fmt.Printf(
				"PID=%d COMM=%s FILE=%s\n",
				event.Tgid,
				bytes.TrimRight(event.Comm[:], "\x00"),
				bytes.TrimRight(event.Filename[:], "\x00"),
			)
		}
	}()
	
	<-stop
	fmt.Println("Exiting...")
}