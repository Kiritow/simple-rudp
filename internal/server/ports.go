package server

import (
	"fmt"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of ports.
type PortRange struct{ First, Last int }

// PortRanges is a set of ports such as "10000-20000,51820". It implements
// [flag.Value]; each Set adds to the set.
type PortRanges []PortRange

// Allows reports whether a client may open port. An empty set allows any
// port, including 0 (let the OS choose).
func (r PortRanges) Allows(port int) bool {
	if port < 0 || port > 65535 {
		return false
	}
	if len(r) == 0 {
		return true
	}
	for _, pr := range r {
		if pr.First <= port && port <= pr.Last {
			return true
		}
	}
	return false
}

// Set parses a comma-separated list of ports and port ranges and adds them to r.
func (r *PortRanges) Set(s string) error {
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := parsePort(lo)
		if err != nil {
			return err
		}
		last := first
		if isRange {
			if last, err = parsePort(hi); err != nil {
				return err
			}
		}
		if first > last {
			return fmt.Errorf("invalid port range %q", part)
		}
		*r = append(*r, PortRange{first, last})
	}
	return nil
}

func (r PortRanges) String() string {
	parts := make([]string, len(r))
	for i, pr := range r {
		parts[i] = strconv.Itoa(pr.First)
		if pr.Last != pr.First {
			parts[i] += "-" + strconv.Itoa(pr.Last)
		}
	}
	return strings.Join(parts, ",")
}

func parsePort(s string) (int, error) {
	p, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return int(p), nil
}
