package procfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

// Collector reads the procfs network tables for the current network namespace.
type Collector struct {
	// Root is the procfs mount point. Empty means /proc.
	Root string
	// Now supplies timestamps. Nil means time.Now.
	Now func() time.Time
}

// Result is the output of a collection pass.
type Result struct {
	Sockets      []model.Socket
	Warnings     []string
	SourcesOK    int
	SourcesTried int
}

// Complete reports whether every source could be read.
func (r Result) Complete() bool { return r.SourcesTried > 0 && r.SourcesOK == r.SourcesTried }

// Collect reads TCP, UDP and Unix tables. A failed individual source becomes a
// warning; an error is returned only when every source failed.
func (c Collector) Collect(ctx context.Context) (Result, error) {
	root := c.Root
	if root == "" {
		root = "/proc"
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	netDir := filepath.Join(root, "self", "net")

	var res Result
	type source struct {
		name string
		read func() ([]model.Socket, []string, error)
	}
	sources := []source{
		{"tcp", func() ([]model.Socket, []string, error) {
			return c.readTable(filepath.Join(netDir, "tcp"), func(r *os.File) ([]model.Socket, []string, error) {
				return ParseTCPTable(r, model.ProtocolTCP, now())
			})
		}},
		{"tcp6", func() ([]model.Socket, []string, error) {
			return c.readTable(filepath.Join(netDir, "tcp6"), func(r *os.File) ([]model.Socket, []string, error) {
				return ParseTCPTable(r, model.ProtocolTCP6, now())
			})
		}},
		{"udp", func() ([]model.Socket, []string, error) {
			return c.readTable(filepath.Join(netDir, "udp"), func(r *os.File) ([]model.Socket, []string, error) {
				return ParseUDPTable(r, model.ProtocolUDP, now())
			})
		}},
		{"udp6", func() ([]model.Socket, []string, error) {
			return c.readTable(filepath.Join(netDir, "udp6"), func(r *os.File) ([]model.Socket, []string, error) {
				return ParseUDPTable(r, model.ProtocolUDP6, now())
			})
		}},
		{"unix", func() ([]model.Socket, []string, error) {
			return c.readTable(filepath.Join(netDir, "unix"), func(r *os.File) ([]model.Socket, []string, error) {
				return ParseUnixTable(r, now())
			})
		}},
	}

	res.SourcesTried = len(sources)
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		sockets, warnings, err := src.read()
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", src.name, err))
			continue
		}
		res.SourcesOK++
		res.Sockets = append(res.Sockets, sockets...)
		for _, w := range warnings {
			res.Warnings = append(res.Warnings, w)
		}
	}
	if res.SourcesOK == 0 {
		return res, fmt.Errorf("no procfs network tables could be read under %s", netDir)
	}
	return res, nil
}

func (c Collector) readTable(path string, parse func(*os.File) ([]model.Socket, []string, error)) ([]model.Socket, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return parse(f)
}

// ReadNetNS returns the current network namespace identifier from procfs, or
// an empty string when it cannot be determined.
func ReadNetNS(root string) string {
	if root == "" {
		root = "/proc"
	}
	target, err := os.Readlink(filepath.Join(root, "self", "ns", "net"))
	if err != nil {
		return ""
	}
	return target
}
