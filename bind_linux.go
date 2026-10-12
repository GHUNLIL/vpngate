package main

import "syscall"

// bindControl pins a socket to a network device (SO_BINDTODEVICE) so it egresses through that tunnel.
func bindControl(dev string) func(network, address string, c syscall.RawConn) error {
	if dev == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		if cerr := c.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
		}); cerr != nil {
			return cerr
		}
		return err
	}
}
