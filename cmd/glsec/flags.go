// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"strings"
)

// parseFlags lets flags and positional arguments be interspersed. FlagSet
// still validates names and values; its registered types decide which flags
// consume the next argument, even when that value starts with a dash.
func parseFlags(fs *flag.FlagSet, args []string) error {
	var options, positional []string
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			positional = append(positional, args...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			continue
		}
		options = append(options, arg)
		name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
		name, _, inline := strings.Cut(name, "=")
		option := fs.Lookup(name)
		if option == nil || inline {
			continue
		}
		if boolean, ok := option.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if len(args) == 0 {
			// Do not let our inserted terminator become a missing flag value.
			return fs.Parse(options)
		}
		options = append(options, args[0])
		args = args[1:]
	}
	return fs.Parse(append(append(options, "--"), positional...))
}
