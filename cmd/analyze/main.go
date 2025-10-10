// Package main contains the entry logic for analyze

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/chrisfenner/slh-dsa-rls/pkg/slhdsa"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	"golang.org/x/term"
)

var (
	tableFormat = flag.String("table_format", "console", "style for the output, one of ('console', 'markdown', 'csv')")
)

func main() {
	flag.Parse()
	extraArgs := flag.Args()
	if len(extraArgs) != 0 {
		fmt.Fprintf(os.Stderr, "unrecognized arguments: %v", strings.Join(extraArgs, ", "))
		os.Exit(1)
	}

	if err := mainErr(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

type namedParms struct {
	id string
	slhdsa.ParameterSet
}

func mainErr() error {
	var parms []namedParms

	// Print a prompt if the program is being run from an interactive terminal
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Printf("Enter the values (id, overuse, n, d, h', a, k, lg_w) for each parameter set, or an empty line to finish.\n")
	}

	// Read the parameter sets from the input.
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		id, parm, err := getParameterSetFromLine(line)
		if err != nil {
			return err
		}
		parms = append(parms, namedParms{id: id, ParameterSet: *parm})
	}

	t := table.NewWriter()
	var render func() string
	switch strings.ToLower(*tableFormat) {
	case "console":
		render = t.Render
	case "markdown":
		render = t.RenderMarkdown
	case "csv":
		render = t.RenderCSV
	default:
		fmt.Fprintf(os.Stderr, "unrecognized table format: %v", *tableFormat)
		os.Exit(1)
	}

	t.AppendHeader(table.Row{
		"id",
		"s",
		"h",
		"d",
		"h'",
		"a",
		"k",
		"w",
		"m",
		"sig bytes",
		"sign work",
		"verify work",
		"sigs",
		"sigs at reduced",
	})

	for _, parm := range parms {
		t.AppendRow(table.Row{
			parm.id,                  // "id",
			parm.TargetSecurityLevel, // "s",
			parm.HypertreeHeight(),   // "h",
			parm.D,                   // "d",
			parm.HPrime,              // "h'",
			parm.T,                   // "a",
			parm.K,                   // "k",
			parm.LgW,                 // "lg_w",
			parm.M(),                 // "m",
			parm.SignatureSize(),     // "sig bytes",
			parm.SignatureHashes(),   // "sign work",
			parm.VerifyHashes(),      // "verify work",
			parm.SignaturesAtLevel(parm.TargetSecurityLevel),  // "sigs",
			parm.SignaturesAtLevel(parm.OveruseSecurityLevel), // "sigs at {fallbackSecurityLevel}",
		})
	}

	t.SetStyle(table.StyleColoredDark)
	t.Style().Title.Align = text.AlignCenter
	title := "Selected Parameter Sets"
	t.SetTitle(title)
	fmt.Println(render())
	return nil
}

func getParameterSetFromLine(line string) (string, *slhdsa.ParameterSet, error) {
	split := strings.Split(line, " ")
	if len(split) != 8 {
		return "", nil, fmt.Errorf("expected format: (id, overuse, n, d, h', a, k, lg_w); got %d fields", len(split))
	}
	id := split[0]
	overuse, err := strconv.ParseInt(split[1], 10, 32)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse overuse from %q: %v", split[1], err)
	}
	n, err := strconv.ParseInt(split[2], 10, 32)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse n from %q: %v", split[2], err)
	}
	d, err := strconv.ParseInt(split[3], 10, 32)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse d from %q: %v", split[3], err)
	}
	hp, err := strconv.ParseInt(split[4], 10, 32)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse h' from %q: %v", split[4], err)
	}
	a, err := strconv.ParseInt(split[5], 10, 32)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse a from %q: %v", split[5], err)
	}
	k, err := strconv.ParseInt(split[6], 10, 32)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse k from %q: %v", split[6], err)
	}
	lgw, err := strconv.ParseInt(split[7], 10, 32)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse lg_w from %q: %v", split[7], err)
	}

	return id, &slhdsa.ParameterSet{
		TargetSecurityLevel:  int(n) * 8,
		OveruseSecurityLevel: int(overuse),
		D:                    int(d),
		HPrime:               int(hp),
		T:                    int(a),
		K:                    int(k),
		LgW:                  int(lgw),
	}, nil
}
