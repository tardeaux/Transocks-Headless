package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/transocks-headless/transocks-headless/internal/config"
	"github.com/transocks-headless/transocks-headless/internal/provider"
	"github.com/transocks-headless/transocks-headless/internal/supervisor"
)

var version = "dev"

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if err := run(os.Args[1:]); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "daemon"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := fs.String("config", "/etc/config/transocks", "UCI configuration path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch command {
	case "version":
		fmt.Println(version)
		return nil
	case "status":
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		data, err := readBoundedFile(cfg.StateFile, 1<<20)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println(`{"status":"stopped"}`)
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		if len(data) == 0 || data[len(data)-1] != '\n' {
			fmt.Println()
		}
		return nil
	case "check":
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		creds, err := config.LoadCredentials(cfg.CredentialFile)
		if err != nil {
			return err
		}
		if err := creds.Validate(); err != nil {
			return err
		}
		fmt.Printf("configuration valid; auth_by=%s; domains=%d\n", creds.AuthBy, len(cfg.APIDomains))
		return nil
	case "daemon":
		return daemon(*configPath)
	default:
		return fmt.Errorf("unknown command %q (use daemon, check, status, or version)", command)
	}
}

func daemon(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return errors.New("service disabled in UCI configuration")
	}
	creds, err := config.LoadCredentials(cfg.CredentialFile)
	if err != nil {
		return err
	}
	if err := creds.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.RunDir, 0o700); err != nil {
		return fmt.Errorf("create run directory: %w", err)
	}
	if err := os.Chmod(cfg.RunDir, 0o700); err != nil {
		return fmt.Errorf("secure run directory: %w", err)
	}
	stateDir := filepath.Dir(cfg.StateFile)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	defer os.Remove(filepath.Join(cfg.RunDir, "sing-box.json"))
	defer os.Remove(filepath.Join(cfg.RunDir, "sing-box.json.candidate"))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client := provider.New(cfg)
	defer client.Close()
	manager := supervisor.New(cfg, client, creds, version)
	if err := manager.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}
