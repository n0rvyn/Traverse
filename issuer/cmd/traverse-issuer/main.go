package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"

	"github.com/n0rvyn/Traverse/issuer/internal/issuance"
)

func run() int {
	return runReady(nil)
}

func runReady(ready func()) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if guardOwner() != nil {
		json.NewEncoder(os.Stdout).Encode(issuance.Result{Version: 1, Status: "failed", Code: "owner_unavailable"})
		return 1
	}
	if ready != nil {
		ready()
	}
	return issuance.Run(ctx, contextInput{ctx}, os.Stdout)
}

func main() { os.Exit(run()) }
