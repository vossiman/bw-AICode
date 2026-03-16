package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	configPath := flag.String("config", "", "Path to allowlist JSON config")
	socketPath := flag.String("socket", "", "Path to Unix socket to listen on")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "Path to real Docker socket")
	flag.Parse()

	if *configPath == "" || *socketPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: bw-docker-guard --config <path> --socket <path>")
		os.Exit(1)
	}

	fmt.Printf("config=%s socket=%s docker=%s\n", *configPath, *socketPath, *dockerSocket)
}
