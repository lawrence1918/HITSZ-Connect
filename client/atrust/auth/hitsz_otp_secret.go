package auth

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const maxHITSZOTPSecretFileSize = 8 * 1024

// resolveHITSZOTPSecret chooses the least surprising source for an OTP seed:
// an explicit value first, then a protected file, then an interactive prompt.
// It deliberately never writes the seed into the persisted aTrust state.
func resolveHITSZOTPSecret(opts HITSZSSOLogin) (string, error) {
	if secret := strings.TrimSpace(opts.MFAOTPSecret); secret != "" {
		return secret, nil
	}
	if path := strings.TrimSpace(opts.MFAOTPSecretFile); path != "" {
		return readHITSZOTPSecretFile(path)
	}
	if opts.NonInteractive {
		return "", errors.New("HITSZ OTP secret required in non-interactive mode (use --mfa-otp-secret or --mfa-otp-secret-file)")
	}
	return promptHITSZOTPSecret()
}

func readHITSZOTPSecretFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read HITSZ OTP secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("HITSZ OTP secret file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("HITSZ OTP secret file must not be group/world-readable (chmod 600)")
	}
	if info.Size() > maxHITSZOTPSecretFileSize {
		return "", errors.New("HITSZ OTP secret file is too large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read HITSZ OTP secret file: %w", err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", errors.New("HITSZ OTP secret file is empty")
	}
	return secret, nil
}

func promptHITSZOTPSecret() (string, error) {
	fmt.Fprint(os.Stderr, "HITSZ OTP/TOTP secret: ")

	// stty is available on the macOS and Unix terminals supported by this
	// client. If stdin is a terminal and echo cannot be disabled, fail rather
	// than unexpectedly showing a long-lived OTP seed on screen.
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		command := exec.Command("stty", "-echo")
		command.Stdin = os.Stdin
		if err := command.Run(); err != nil {
			return "", errors.New("unable to securely read HITSZ OTP secret; use --mfa-otp-secret-file")
		}
		defer func() {
			command := exec.Command("stty", "echo")
			command.Stdin = os.Stdin
			_ = command.Run()
			fmt.Fprintln(os.Stderr)
		}()
	}

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read HITSZ OTP secret: %w", err)
	}
	secret := strings.TrimSpace(line)
	if secret == "" {
		return "", errors.New("HITSZ OTP secret is empty")
	}
	return secret, nil
}
