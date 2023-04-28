package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tc.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	err = attachProgram(ifaceName, objs.bpfPrograms.Classifier)
	if err != nil {
		log.Fatalf("could not attach XDTCP program: %s", err)
	}

	log.Printf("Attached TC program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.RateMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

func u32toIPv4(ip_address uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d",
        ip_address&0xFF,
        (ip_address>>8)&0xFF,
        (ip_address>>16)&0xFF,
        (ip_address>>24)&0xFF)
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		dstIP := key // IPv4 source address in network byte order.
		rate := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", u32toIPv4(dstIP), rate))
	}
	return sb.String(), iter.Err()
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

func attachProgram(deviceName string, prog *ebpf.Program) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}

	linkList, err := netlink.LinkList()
	if err != nil {
		return err
	}

	linkRE, err := regexp.Compile(deviceName)
	if err != nil {
		return fmt.Errorf("unable to compile device name regex %q: %w", deviceName, err)
	}
	for _, link := range linkList {
		if !linkRE.MatchString(link.Attrs().Name) {
			continue
		}
		if err := replaceQdisc(link); err != nil {
			return fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
		}

		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Priority:  1,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         fmt.Sprintf("skouter-%s", link.Attrs().Name),
			DirectAction: true,
		}

		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("replacing tc filter: %w", err)
		}
	}

	return nil
}
