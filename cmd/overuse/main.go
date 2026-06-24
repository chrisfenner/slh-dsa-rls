// Package main contains the entry logic for overuse

package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
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

func mainErr() error {
	var parms *slhdsa.ParameterSet

	// Print a prompt if the program is being run from an interactive terminal
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Printf("Enter the values (n, d, h', a, k, lg_w) for the parameter set\n")
	}

	// Read the parameter set from the input.
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	line := scanner.Text()

	var err error
	parms, err = getParameterSetFromLine(line)
	if err != nil {
		return err
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
		"sigs",
		"security level",
	})

	// Compute the security level for various values of overuse until it drops below 64 bits
	sigs := math.Floor(parms.SignaturesAtLevel(parms.TargetSecurityLevel))
	for {
		security := parms.SecurityLevel(float64(sigs))
		if security < 64 {
			break
		}
		t.AppendRow(table.Row{
			sigs,
			security,
		})
		sigs += 0.25
	}

	t.SetStyle(table.StyleColoredDark)
	t.Style().Title.Align = text.AlignCenter
	t.SetTitle("Overuse Security Level")
	fmt.Println(render())
	return nil
}

func getParameterSetFromLine(line string) (*slhdsa.ParameterSet, error) {
	split := strings.Split(line, " ")
	if len(split) != 6 {
		return nil, fmt.Errorf("expected format: (n, d, h', a, k, lg_w); got %d fields", len(split))
	}
	n, err := strconv.ParseInt(split[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse n from %q: %v", split[2], err)
	}
	d, err := strconv.ParseInt(split[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse d from %q: %v", split[3], err)
	}
	hp, err := strconv.ParseInt(split[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse h' from %q: %v", split[4], err)
	}
	a, err := strconv.ParseInt(split[3], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse a from %q: %v", split[5], err)
	}
	k, err := strconv.ParseInt(split[4], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse k from %q: %v", split[6], err)
	}
	lgw, err := strconv.ParseInt(split[5], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse lg_w from %q: %v", split[7], err)
	}

	return &slhdsa.ParameterSet{
		TargetSecurityLevel: int(n) * 8,
		D:                   int(d),
		HPrime:              int(hp),
		T:                   int(a),
		K:                   int(k),
		LgW:                 int(lgw),
	}, nil
}
