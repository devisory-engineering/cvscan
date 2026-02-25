package main

import (
	"fmt"
	"os"
)

var (
	version    = "dev"
	apiBaseURL = "http://localhost:8080"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Printf("cvscan %s\n", version)
	return nil
}
