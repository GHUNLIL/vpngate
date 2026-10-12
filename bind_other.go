//go:build !linux

package main

import "syscall"

// Device binding is Linux-only; elsewhere sockets use the default route (development / tests).
func bindControl(string) func(network, address string, c syscall.RawConn) error { return nil }
