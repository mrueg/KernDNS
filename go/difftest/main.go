// difftest sends the same queries to two DNS servers (A: CoreDNS, B:
// KernDNS) and reports every difference in the responses.
//
// Queries are generated from a zone file: every owner name, a few names
// below each (to exercise wildcards, empty non-terminals and NXDOMAIN),
// times a set of record types, with and without the DNSSEC OK bit.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var types = []uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSOA, dns.TypeMX, dns.TypeSRV, dns.TypeTXT,
	dns.TypeCNAME, dns.TypeDNAME, dns.TypePTR, dns.TypeDS, dns.TypeDNSKEY, dns.TypeNSEC,
	dns.TypeHTTPS, dns.TypeSVCB, dns.TypeCAA, dns.TypeANY,
}

func main() {
	a := flag.String("a", "", "address of server A (reference)")
	b := flag.String("b", "", "address of server B (under test)")
	zone := flag.String("zone", "", "zone file to generate queries from")
	origin := flag.String("origin", "", "zone origin")
	maxDiffs := flag.Int("show", 20, "differences to print")
	printOrigin := flag.Bool("print-origin", false, "print the zone's SOA owner name and exit")
	queryFile := flag.String("queries", "", "file with 'name type' lines to send instead of zone-derived queries")
	ignoreSerial := flag.Bool("ignore-soa-serial", false, "compare SOA records without their serial")
	dnssecKey := flag.String("dnssec-key", "", "DNSKEY file: compare RRSIGs without signature and times, and verify every RRSIG of both servers with this key")
	flag.Parse()
	normalizeSerial = *ignoreSerial
	if *dnssecKey != "" {
		f, err := os.Open(*dnssecKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		rr, err := dns.ReadRR(f, *dnssecKey)
		f.Close()
		k, ok := rr.(*dns.DNSKEY)
		if err != nil || !ok {
			fmt.Fprintln(os.Stderr, "no DNSKEY in", *dnssecKey, err)
			os.Exit(2)
		}
		verifyKey = k
	}

	if *queryFile != "" {
		os.Exit(runQueries(*a, *b, *queryFile, *maxDiffs))
	}

	if *printOrigin {
		f, err := os.Open(*zone)
		if err != nil {
			os.Exit(2)
		}
		zp := dns.NewZoneParser(f, ".", *zone)
		for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
			if rr.Header().Rrtype == dns.TypeSOA {
				fmt.Println(rr.Header().Name)
				return
			}
		}
		os.Exit(1)
	}

	f, err := os.Open(*zone)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	zp := dns.NewZoneParser(f, dns.Fqdn(*origin), *zone)
	zp.SetIncludeAllowed(true)
	seen := map[string]bool{}
	var names []string
	add := func(n string) {
		n = strings.ToLower(n)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		owner := rr.Header().Name
		if strings.HasPrefix(owner, "*.") {
			owner = owner[2:]
			add("wild." + owner)
			add("a.b.wild." + owner)
		}
		add(owner)
		add("nx." + owner)
		add("a.nx." + owner)
		switch x := rr.(type) {
		case *dns.CNAME:
			add(x.Target)
		case *dns.DNAME:
			add("x." + owner)
		}
	}
	add("nx-" + dns.Fqdn(*origin))
	sort.Strings(names)

	c := &dns.Client{Timeout: 2 * time.Second}
	total, diffs := 0, 0
	for _, n := range names {
		for _, t := range types {
			for _, do := range []bool{false, true} {
				total++
				m := new(dns.Msg)
				m.SetQuestion(n, t)
				m.SetEdns0(4096, do)
				ra, _, errA := c.Exchange(m.Copy(), *a)
				rb, _, errB := c.Exchange(m.Copy(), *b)
				d := compare(ra, errA, rb, errB)
				if d == "" {
					continue
				}
				diffs++
				if diffs <= *maxDiffs {
					fmt.Printf("DIFF %s %s do=%v\n%s\n", n, dns.TypeToString[t], do, d)
				}
			}
		}
	}
	fmt.Printf("%d queries, %d differences\n", total, diffs)
	if diffs > 0 {
		os.Exit(1)
	}
}

var normalizeSerial bool

// verifyKey, if set, signs both servers' answers: RRSIGs are compared
// without their signature and validity times (randomized ECDSA and
// signing time differ by design) and each one must verify with it.
var verifyKey *dns.DNSKEY

// sigProblems verifies every RRSIG in m made by verifyKey against the
// RRset it covers in the same section.
func sigProblems(m *dns.Msg) []string {
	var out []string
	now := time.Now()
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}
			k := *verifyKey
			k.Hdr.Name = sig.SignerName
			if sig.KeyTag != k.KeyTag() {
				continue // signed by a key we don't know (e.g. RRSIGs from the zone file)
			}
			var set []dns.RR
			for _, x := range sec {
				if x.Header().Rrtype == sig.TypeCovered && strings.EqualFold(x.Header().Name, sig.Header().Name) {
					set = append(set, x)
				}
			}
			if len(set) == 0 {
				out = append(out, "RRSIG covers nothing: "+sig.String())
			} else if err := sig.Verify(&k, set); err != nil {
				out = append(out, fmt.Sprintf("RRSIG does not verify (%v): %s", err, sig.String()))
			} else if !sig.ValidityPeriod(now) {
				out = append(out, "RRSIG not valid now: "+sig.String())
			}
		}
	}
	return out
}

func section(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		if soa, ok := rr.(*dns.SOA); ok && normalizeSerial {
			c := dns.Copy(soa).(*dns.SOA)
			c.Serial = 0
			rr = c
		}
		if sig, ok := rr.(*dns.RRSIG); ok && verifyKey != nil {
			c := dns.Copy(sig).(*dns.RRSIG)
			c.Inception, c.Expiration, c.Signature = 0, 0, "-"
			rr = c
		}
		out = append(out, strings.ToLower(rr.String()))
	}
	sort.Strings(out)
	return out
}

func summary(m *dns.Msg) map[string][]string {
	return map[string][]string{
		"rcode": {dns.RcodeToString[m.Rcode]},
		"flags": {fmt.Sprintf("aa=%v tc=%v ra=%v ad=%v", m.Authoritative, m.Truncated, m.RecursionAvailable, m.AuthenticatedData)},
		"ans":   section(m.Answer),
		"ns":    section(m.Ns),
		"extra": section(m.Extra),
	}
}

func compare(a *dns.Msg, errA error, b *dns.Msg, errB error) string {
	if errA != nil || errB != nil {
		if (errA == nil) != (errB == nil) {
			return fmt.Sprintf("  A error: %v\n  B error: %v", errA, errB)
		}
		return ""
	}
	sa, sb := summary(a), summary(b)
	if verifyKey != nil {
		sa["sigs"], sb["sigs"] = sigProblems(a), sigProblems(b)
	}
	var out []string
	for _, k := range []string{"rcode", "flags", "ans", "ns", "extra", "sigs"} {
		x, y := strings.Join(sa[k], "\n      "), strings.Join(sb[k], "\n      ")
		if x != y {
			out = append(out, fmt.Sprintf("  %s:\n    A:  %s\n    B:  %s", k, x, y))
		}
	}
	return strings.Join(out, "\n")
}

// runQueries sends every "name type" line of path (both with and without
// the DO bit) to both servers and reports differences.
func runQueries(a, b, path string, maxDiffs int) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	c := &dns.Client{Timeout: 2 * time.Second}
	total, diffs := 0, 0
	// what server A answered, so "no differences" can't hide two servers
	// that fail the same way
	rcodes := map[string]int{}
	withAnswers := 0
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		t, ok := dns.StringToType[strings.ToUpper(f[1])]
		if !ok {
			continue
		}
		for _, do := range []bool{false, true} {
			total++
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(f[0]), t)
			m.SetEdns0(4096, do)
			ra, _, errA := c.Exchange(m.Copy(), a)
			rb, _, errB := c.Exchange(m.Copy(), b)
			if ra != nil {
				rcodes[dns.RcodeToString[ra.Rcode]]++
				if len(ra.Answer) > 0 {
					withAnswers++
				}
			}
			if d := compare(ra, errA, rb, errB); d != "" {
				diffs++
				if diffs <= maxDiffs {
					fmt.Printf("DIFF %s %s do=%v\n%s\n", f[0], f[1], do, d)
				}
			}
		}
	}
	var rc []string
	for k, v := range rcodes {
		rc = append(rc, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(rc)
	fmt.Printf("answers from A: %d with records; %s\n", withAnswers, strings.Join(rc, ", "))
	fmt.Printf("%d queries, %d differences\n", total, diffs)
	if diffs > 0 {
		return 1
	}
	return 0
}
