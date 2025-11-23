package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/sotnii/khaos/packetdrop"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "khaos <dropped packets pct>",
	Short:   "Run khaos (alias for khaos block)",
	Aliases: []string{"block"},
	Long: `Khaos is a WIP chaos monkey framework taking leverage of eBPF to control network traffic of applications

	Note: Since XDP handles ingress-only traffic, --ip & --port are compared against values only in incoming traffic.`,
	Args: cobra.MatchAll(cobra.ExactArgs(1)),
	Run:  runRoot,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.khaos.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().StringP("interface", "i", "", "interface to attach the program to directly")
	rootCmd.Flags().StringP("docker", "d", "", "use virtual interface for a specified docker container (the container should be running)")
	rootCmd.Flags().IP("ip", net.IPv4zero, "src ip address to block traffic from where 0.0.0.0 means all destinations")
	rootCmd.Flags().IntP("port", "p", 0, "port number to block traffic from (default 0 - means all ports)")
}

func runRoot(cmd *cobra.Command, args []string) {
	dropPct, err := strconv.Atoi(args[0])
	if err != nil {
		log.Fatal("drop percentage must be an integer")
	}

	var iface *net.Interface = nil
	ifaceName, _ := cmd.Flags().GetString("interface")
	if ifaceName != "" {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatal(err)
		}
	}

	dockerContainer, _ := cmd.Flags().GetString("docker")
	if ifaceName == "" && dockerContainer != "" {
		veth, err := getDockerContainerVeth(dockerContainer)
		if err != nil {
			log.Fatal("failed to get docker container veth: " + err.Error())
		}
		ifaceName = veth
		iface, _ = net.InterfaceByName(veth)
	}

	if iface == nil {
		log.Fatalf("expected --docker or --interface to be passed")
	}

	ip, _ := cmd.Flags().GetIP("ip")
	port, _ := cmd.Flags().GetInt("port")
	pd, err := packetdrop.NewPacketDropper(iface, ip, port, dropPct)
	if err != nil {
		log.Fatalf("Cannot create PacketDropper: %s", err)
	}

	err = pd.Attach()
	if err != nil {
		panic(err)
	}
	defer func() {
		err := pd.Close()
		if err != nil {
			log.Fatalf("Closing packet dropper: %s", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eventTrace, err := pd.TraceEvents(ctx)
	if err != nil {
		log.Fatalf("Tracing events: %s", err)
	}

	log.Printf("Dropping %d%% of incoming packets from %v:%d on %v", dropPct, ip, port, ifaceName)

	droppedCnt := 0
	passedCnt := 0
	for event := range eventTrace {
		fmt.Println(event)
		switch event.Type {
		case packetdrop.TypePass:
			passedCnt++
		case packetdrop.TypeDrop:
			droppedCnt++
		default:
		}
	}

	fmt.Printf("\nTraced %d events, dropped %d, passed %d\n", droppedCnt+passedCnt, droppedCnt, passedCnt)
}

// AI, I know... I'm particularly lazy today

// DockerNetworkSettings represents the relevant part of `docker inspect` output
type DockerNetworkSettings struct {
	NetworkSettings struct {
		SandboxKey string `json:"SandboxKey"`
	} `json:"NetworkSettings"`
}

// getDockerContainerVeth returns the host-side veth peer interface name for a given Docker container.
// It assumes the container uses the default bridge or a custom bridge (veth pair setup).
func getDockerContainerVeth(container string) (string, error) {
	// Step 1: Get the container's network namespace path via `docker inspect`
	inspectOut, err := exec.Command("docker", "inspect", container).Output()
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %q: %w", container, err)
	}

	var inspect []DockerNetworkSettings
	if err := json.Unmarshal(inspectOut, &inspect); err != nil {
		return "", fmt.Errorf("failed to parse docker inspect output: %w", err)
	}
	if len(inspect) == 0 {
		return "", fmt.Errorf("no inspect data returned for container %q", container)
	}

	sandboxKey := inspect[0].NetworkSettings.SandboxKey
	if sandboxKey == "" {
		return "", fmt.Errorf("container %q has no SandboxKey (might not be running or not using bridge network)", container)
	}

	// Step 2: Get container's ip link output using nsenter
	nsenterCmd := exec.Command("nsenter", "-n"+sandboxKey, "ip", "link", "show")
	ipLinkOut, err := nsenterCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run ip link in container netns: %w", err)
	}

	// Step 3: Find the container-side veth (usually eth0) and extract peer index
	// Look for line like: "2: eth0@if40: <...>"
	re := regexp.MustCompile(`^\s*(\d+):\s+([^@:\s]+)@if(\d+):\s+`)
	scanner := strings.Split(string(ipLinkOut), "\n")
	var peerIndex int
	for _, line := range scanner {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			// We assume the first veth-like interface (commonly eth0) is the main one
			// Skip loopback (lo)
			if matches[2] == "lo" {
				continue
			}
			peerIndex, err = strconv.Atoi(matches[3])
			if err != nil {
				continue // should not happen
			}
			break
		}
	}

	if peerIndex == 0 {
		return "", fmt.Errorf("could not find veth peer index in container %q network namespace", container)
	}

	// Step 4: On the host, find the interface with that index
	hostIPLinkOut, err := exec.Command("ip", "link", "show").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run 'ip link show' on host: %w", err)
	}

	hostScanner := strings.Split(string(hostIPLinkOut), "\n")
	for _, line := range hostScanner {
		if strings.HasPrefix(strings.TrimSpace(line), fmt.Sprintf("%d:", peerIndex)) {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				iface := strings.TrimSpace(parts[1])
				return iface[:strings.Index(iface, "@")], nil
			}
		}
	}

	return "", fmt.Errorf("host veth peer with index %d not found", peerIndex)
}
