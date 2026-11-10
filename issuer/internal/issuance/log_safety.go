package issuance

import (
	legolog "github.com/go-acme/lego/v5/log"
	"io"
	"log/slog"
)

func init() {
	// Library errors/warnings can include CA response bodies, tokens and URLs.
	// The cold helper exposes only its fixed result schema, never those logs.
	legolog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}
