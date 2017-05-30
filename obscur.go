// +build main

package main

import "github.com/strickyak/obscur"

import (
	"flag"
	"fmt"
	"os"
)

var encrypt = flag.Bool("e", false, "encrypt mode")
var decrypt = flag.Bool("d", false, "decrypt mode")
var key = flag.String("k", "", "secret key")

func main() {
	flag.Parse()
	if !*encrypt && !*decrypt || *encrypt && *decrypt || len(*key) < 1 {
		fmt.Fprintf(os.Stderr, `Usage:
  obscur -e -k 'secret_key' <plaintext  >cyphertext
  obscur -d -k 'secret_key' <cyphertext >plaintext
`)
		os.Exit(2)
	}
	obscur.NewProcessor(*encrypt, *key).ProcessStream(os.Stdin, os.Stdout)
}
