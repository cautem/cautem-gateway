package main

import (
	"fmt"
	"os"

	"github.com/cautem/quarshell-gateway/internal/app/gateway"
)

func main() {
	if err := gateway.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
