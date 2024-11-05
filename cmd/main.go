package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [.pfx file]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	iPfx := os.Args[1]
	oPfx := addFilenameSuffix(iPfx, "_new")

	iPfxData, err := os.ReadFile(iPfx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to Read PFX File: %s\n", err.Error())
		exit(1)
	}

	fmt.Printf("[+] Imported File '%s'\n", filepath.Base(iPfx))

	// get the input PFX password
	oldPw := getPass("Current PFX Password")
	key, crt, cas, err := pkcs12.DecodeChain(iPfxData, oldPw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to Decode PFX File: %s\n", err.Error())
		exit(1)
	}

	fmt.Println("[+] Successfully decoded the original pfx")

	// get the output PFX password and a second confirmation entry
	newPw1 := getPass("Enter New PFX Password")
	newPw2 := getPass("Confirm New PFX Password")

	if newPw1 != newPw2 {
		fmt.Fprintln(os.Stderr, "New Passwords Do Not Match")
		exit(1)
	}

	oPfxData, err := pkcs12.Modern.Encode(key, crt, cas, newPw1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to Encode New PFX File: %s\n", err.Error())
		exit(1)
	}

	if err := os.WriteFile(oPfx, oPfxData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to Write New PFX File: %s\n", err.Error())
		exit(1)
	}

	fmt.Printf("[+] Created New PFX File '%s'\n", oPfx)
	exit(0)
}

func getPass(prompt string) string {
	fmt.Printf("%s: ", prompt)

	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to read password: %s", err.Error())
		os.Exit(1)
	}

	return string(pw)
}

func addFilenameSuffix(filename, suffix string) string {
	basename := filepath.Base(filename)
	ext := filepath.Ext(basename)
	basenameNoExt := strings.TrimSuffix(basename, ext)
	return filepath.Join(filepath.Dir(basename), fmt.Sprintf("%s%s%s", basenameNoExt, suffix, ext))
}

func waitForEnter() {
	fmt.Println("Press Enter to exit...")
	fmt.Scanln()
}

func exit(code int) {
	waitForEnter()
	os.Exit(code)
}
