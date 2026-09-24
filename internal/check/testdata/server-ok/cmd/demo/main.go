// Command demo is a server plugin that calls one vendor.
package main

import (
	"fmt"
	"os"
)

const vendor = "https://api.example-vendor.com/v1/coach"

func main() {
	fmt.Fprintln(os.Stdout, vendor)
}
