package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/markpash/find-bad-middleboxes/internal/pidfd"
	"github.com/markpash/find-bad-middleboxes/internal/probe"
	"golang.org/x/sys/unix"
)

func main() {
	pid := flag.Uint64("pid", 0, "provide a pid to get socket file descriptor and set TCP_SAVED_SYN sockopt")
	flag.Parse()

	if *pid != 0 {
		if err := stealAndSetSockOpt(*pid); err != nil {
			panic(err)
		}
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)

	go func() {
		<-s
		signal.Stop(s)
		cancel()
	}()

	if err := probe.Run(ctx); err != nil {
		panic(err)
	}
}

func stealAndSetSockOpt(pid uint64) error {
	fds, err := pidfd.Files(int(pid))
	if err != nil {
		return err
	}

	for _, fd := range fds {
		if err := unix.SetsockoptInt(int(fd.Fd()), unix.SOL_TCP, unix.TCP_SAVE_SYN, 1); err != nil {
			return err
		}
	}
	return nil
}

func panic(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}
