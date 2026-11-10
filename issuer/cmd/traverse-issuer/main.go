package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/n0rvyn/Traverse/issuer/internal/issuance"
)

func run() int {
	owner, err := ownerArgument(os.Args[1:])
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(issuance.Result{Version: 1, Status: "failed", Code: "invalid_invocation"})
		return 1
	}
	return runOwnedReady(owner, nil)
}

func ownerArgument(arguments []string) (int, error) {
	if len(arguments) == 0 {
		return 0, nil
	}
	if len(arguments) != 2 || arguments[0] != "--supervisor-pid" {
		return 0, strconv.ErrSyntax
	}
	for _, c := range arguments[1] {
		if c < '0' || c > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	owner, err := strconv.ParseInt(arguments[1], 10, 32)
	if err != nil || owner <= 1 {
		return 0, strconv.ErrSyntax
	}
	return int(owner), nil
}

func runReady(ready func()) int {
	return runOwnedReady(0, ready)
}

func runOwnedReady(owner int, ready func()) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if guardOwner(owner) != nil {
		json.NewEncoder(os.Stdout).Encode(issuance.Result{Version: 1, Status: "failed", Code: "owner_unavailable"})
		return 1
	}
	if ready != nil {
		ready()
	}
	return issuance.Run(ctx, contextInput{ctx}, os.Stdout)
}

func main() { os.Exit(run()) }
