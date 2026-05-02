package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel tracer ./bpf/tracer.c -- -I./bpf

const (
	toolName    = "findo"
	toolVersion = "v0.1.0"
	toolAuthor  = "maniakh"
)

const (
	evtExec = 1
	evtOpen = 2
	evtSetuid = 3
)

type Event struct {
	EType uint32
	PID   uint32
	PPID  uint32
	UID   uint32
	Comm  [16]byte
	PComm [16]byte
	Arg   [128]byte
}

type View struct {
	Type, Comm, PComm, Arg string
	PID, PPID, UID         uint32
}

type runtimeState struct {
	whitelistPath string
	whitelist     []string
	dedupWindow   time.Duration
	lastSeen      map[string]time.Time
	startTime     time.Time
	totalEvents   uint64
	totalAlerts   uint64
	alertsByRule  map[string]uint64
	mu            sync.RWMutex
}

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "-h", "--help", "help":
		printHelp()
		return
	case "-v", "--version", "version":
		fmt.Printf("%s %s @%s\n", toolName, toolVersion, toolAuthor)
		return
	case "run":
		// default behavior
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}

	printBanner()

	state := buildRuntimeState()

	logPath := os.Getenv("EBPF_TOOL_LOG")
	if logPath == "" {
		logPath = "findo.log"
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fatalf("open log file: %v", err)
	}
	defer logf.Close()

	if err := rlimit.RemoveMemlock(); err != nil {
		fatalf("rlimit: %v", err)
	}

	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		fatalf("load bpf: %v", err)
	}
	defer objs.Close()

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		fatalf("attach execve: %v", err)
	}
	defer tpExec.Close()

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		fatalf("attach openat: %v", err)
	}
	defer tpOpen.Close()

	tpSetuid, err := link.Tracepoint("syscalls", "sys_enter_setuid", objs.HandleSetuid, nil)
	if err != nil {
		fatalf("attach setuid: %v", err)
	}
	defer tpSetuid.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()
	startConsole(stop, state, logPath)

	fmt.Println("[*] findo running (execve+openat+setuid). Ctrl+C to exit")
	fmt.Println("[*] type -h for runtime commands")
	fmt.Fprintf(logf, "%s [INFO] started log=%s\n", now(), logPath)
	if len(state.whitelist) > 0 {
		fmt.Printf("[*] whitelist loaded: %d entries\n", len(state.whitelist))
	}
	fmt.Printf("[*] dedup window: %ds\n", int(state.dedupWindow.Seconds()))
	printTableHeader()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Fprintf(logf, "%s [INFO] stopped\n", now())
				printStats(state)
				return
			}
			continue
		}
		var ev Event
		if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		state.mu.Lock()
		state.totalEvents++
		state.mu.Unlock()

		v := view(ev)
		if rule, msg := detect(v); rule != "" {
			if isWhitelisted(rule, v, state.whitelist) {
				continue
			}
			if !shouldEmit(state, fingerprint(rule, v)) {
				continue
			}
			printAlertRow(rule, v, msg)
			line := fmt.Sprintf("%s [ALERT %s] pid=%d uid=%d %s parent=%s arg=%s -- %s",
				now(), rule, v.PID, v.UID, v.Comm, v.PComm, v.Arg, msg)
			fmt.Fprintln(logf, line)
			state.mu.Lock()
			state.totalAlerts++
			state.alertsByRule[rule]++
			state.mu.Unlock()
		}
	}
}

// detect uygulanan kurallar:
//   - tmp_exec       : world-writable dizinden binary çalıştırma
//   - web_shell      : web sunucusu altında shell süreç
//   - downloader     : shell altında curl/wget (suspicious download)
//   - credential     : /etc/shadow veya .ssh anahtarı okuma
//   - kernel_tamper  : /proc/kcore, /dev/mem, /dev/kmem erişimi
//   - priv_esc       : şüpheli yetki yükseltme girişimi/sonucu
func detect(v View) (rule, msg string) {
	switch v.Type {
	case "exec":
		switch {
		case hasAnyPrefix(v.Arg, "/tmp/", "/dev/shm/", "/var/tmp/"):
			return "tmp_exec", "world-writable directory execution"
		case v.UID == 0 && isShell(v.Comm) && !isLegitPrivParent(v.PComm):
			return "priv_esc", "root shell from unusual parent"
		case isShell(v.Comm) && isWebServer(v.PComm):
			return "web_shell", "shell spawned by web server"
		case (v.Comm == "curl" || v.Comm == "wget") && isShell(v.PComm):
			return "downloader", "downloader executed under a shell"
		}
	case "open":
		switch {
		case v.Arg == "/etc/shadow" || strings.Contains(v.Arg, "/.ssh/id_"):
			return "credential", "sensitive credential file read"
		case v.Arg == "/proc/kcore" || v.Arg == "/dev/mem" || v.Arg == "/dev/kmem":
			return "kernel_tamper", "kernel memory access"
		}
	case "setuid":
		if v.UID != 0 {
			return "priv_esc", "non-root process attempted setuid"
		}
	}
	return "", ""
}

func view(e Event) View {
	t := "exec"
	if e.EType == evtOpen {
		t = "open"
	} else if e.EType == evtSetuid {
		t = "setuid"
	}
	return View{
		Type: t, PID: e.PID, PPID: e.PPID, UID: e.UID,
		Comm: cstr(e.Comm[:]), PComm: cstr(e.PComm[:]), Arg: cstr(e.Arg[:]),
	}
}

func isShell(s string) bool {
	switch s {
	case "bash", "sh", "dash", "zsh", "ksh":
		return true
	}
	return false
}

func isWebServer(s string) bool {
	switch s {
	case "nginx", "apache2", "httpd", "php-fpm", "node":
		return true
	}
	return false
}

func isLegitPrivParent(s string) bool {
	switch s {
	case "sudo", "su", "login", "sshd", "systemd", "init":
		return true
	}
	return false
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func now() string {
	return time.Now().Format(time.RFC3339)
}

func printBanner() {
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║  ______ _ _   _ ____   ___          ║")
	fmt.Println("║ |  ____| | \\ | |  _ \\ / _ \\         ║")
	fmt.Println("║ | |__  | |  \\| | | | | | | |        ║")
	fmt.Println("║ |  __| | | . ` | | | | | | |        ║")
	fmt.Println("║ | |    | | |\\  | |_| | |_| |        ║")
	fmt.Println("║ |_|    |_|_| \\_|____/ \\___/         ║")
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Printf("║  %-36s║\n", toolName+" "+toolVersion)
	fmt.Printf("║  %-36s║\n", "@"+toolAuthor)
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println()
}

func printHelp() {
	fmt.Printf("findo (@%s)\n", toolAuthor)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  findo run                Start detector (default)")
	fmt.Println("  findo -h | --help        Show help")
	fmt.Println("  findo -v | --version     Show version")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  EBPF_TOOL_LOG            Log file path (default: findo.log)")
	fmt.Println("  FINDO_WHITELIST          Whitelist file path (default: whitelist.txt)")
	fmt.Println("  FINDO_DEDUP_SEC          Alert dedup window seconds (default: 10)")
	fmt.Println()
	fmt.Println("Runtime commands (while running):")
	fmt.Println("  -h, help                 Show help")
	fmt.Println("  -v, version              Show version")
	fmt.Println("  stats                    Show runtime counters")
	fmt.Println("  open whitelist           Show whitelist file")
	fmt.Println("  open log                 Show last log lines")
	fmt.Println("  exit, quit               Stop detector")
}

func startConsole(stop context.CancelFunc, state *runtimeState, logPath string) {
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			cmd := strings.TrimSpace(sc.Text())
			switch cmd {
			case "":
				continue
			case "-h", "--help", "help":
				printHelp()
			case "-v", "--version", "version":
				fmt.Printf("%s %s @%s\n", toolName, toolVersion, toolAuthor)
			case "stats":
				printStats(state)
			case "open whitelist":
				showFile(state.whitelistPath, 200)
			case "open log":
				showTail(logPath, 20, 400)
			case "exit", "quit":
				fmt.Println("[*] stopping findo...")
				stop()
				return
			default:
				fmt.Printf("[*] unknown runtime command: %s (type -h)\n", cmd)
			}
		}
	}()
}

func buildRuntimeState() *runtimeState {
	wlPath := os.Getenv("FINDO_WHITELIST")
	if wlPath == "" {
		wlPath = "whitelist.txt"
	}
	wl, err := loadWhitelist(wlPath)
	if err != nil {
		// whitelist optional: dosya yoksa sessiz geç
		wl = nil
	}

	dedupSec := 10
	if raw := strings.TrimSpace(os.Getenv("FINDO_DEDUP_SEC")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			dedupSec = n
		}
	}

	return &runtimeState{
		whitelistPath: wlPath,
		whitelist:   wl,
		dedupWindow: time.Duration(dedupSec) * time.Second,
		lastSeen:    make(map[string]time.Time),
		startTime:   time.Now(),
		alertsByRule: make(map[string]uint64),
	}
}

func loadWhitelist(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, strings.ToLower(s))
	}
	return out, nil
}

func isWhitelisted(rule string, v View, list []string) bool {
	if len(list) == 0 {
		return false
	}
	rule = strings.ToLower(rule)
	comm := strings.ToLower(v.Comm)
	pcomm := strings.ToLower(v.PComm)
	arg := strings.ToLower(v.Arg)
	for _, w := range list {
		if w == rule || strings.Contains(comm, w) || strings.Contains(pcomm, w) || strings.Contains(arg, w) {
			return true
		}
	}
	return false
}

func fingerprint(rule string, v View) string {
	return fmt.Sprintf("%s|%d|%d|%s|%s|%s", rule, v.PID, v.UID, v.Comm, v.PComm, v.Arg)
}

func shouldEmit(state *runtimeState, key string) bool {
	if state.dedupWindow <= 0 {
		return true
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	now := time.Now()
	last, ok := state.lastSeen[key]
	if ok && now.Sub(last) < state.dedupWindow {
		return false
	}
	state.lastSeen[key] = now
	return true
}

func printStats(state *runtimeState) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	uptime := int(time.Since(state.startTime).Seconds())
	fmt.Printf("\n[*] stats: uptime=%ds events=%d alerts=%d\n", uptime, state.totalEvents, state.totalAlerts)
	if len(state.alertsByRule) == 0 {
		fmt.Println("    rules: (no alerts yet)\n")
		return
	}
	keys := make([]string, 0, len(state.alertsByRule))
	for k := range state.alertsByRule {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("    - %-14s %d\n", k, state.alertsByRule[k])
	}
	fmt.Println()
}

func printTableHeader() {
	fmt.Println("TIME       RULE          PID   UID   COMM       PARENT     ARG")
	fmt.Println("---------- ------------ ----- ----- ---------- ---------- ------------------------------")
}

func printAlertRow(rule string, v View, msg string) {
	_ = msg // log file full detay içeriyor, terminal tabloyu kısa tutuyoruz
	fmt.Printf("%-10s %-12s %-5d %-5d %-10s %-10s %-30s\n",
		time.Now().Format("15:04:05"),
		trim(rule, 12),
		v.PID,
		v.UID,
		trim(v.Comm, 10),
		trim(v.PComm, 10),
		trim(v.Arg, 30),
	)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func showFile(path string, maxLines int) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[*] cannot open %s: %v\n", path, err)
		return
	}
	fmt.Printf("[*] %s\n", path)
	lines := strings.Split(string(b), "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	for _, ln := range lines {
		fmt.Println(ln)
	}
}

func showTail(path string, n, maxLines int) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[*] cannot open %s: %v\n", path, err)
		return
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	fmt.Printf("[*] last %d lines of %s\n", len(lines), path)
	for _, ln := range lines {
		fmt.Println(ln)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
