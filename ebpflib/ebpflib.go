package ebpflib

import (
  "fmt"
  "io"
  "os"
  "strings"
  "io/ioutil"
  "encoding/binary"
  "regexp"
  "debug/elf"
  "strconv"
  "context"
//  "syscall"
  "bytes"

  "github.com/cilium/ebpf"
  "github.com/cilium/ebpf/perf"
  "golang.org/x/sys/unix"
"github.com/vishvananda/netlink"
)


// Collection defines an interface for loading maps and
// programs from an ELF ebpf program file
type Collection interface {
  // Loads a map from a collection
  LoadMap(mapName string) (Map, io.Closer, error)
  // Loads a program from a collection
  LoadProgram(programName string) (Program, io.Closer, error)
}

type collection struct {
  coll *ebpf.Collection
}

// Map is an ebpf map
type Map interface {
  // Lookup retrieves a value from a Map.
  Lookup(key, valueOut interface{}) error
  // NewReaderFromPerfEventMap creates a new reader from a perf event array, so that
  // events can be read from it
  NewReaderFromPerfEventMap() (EventsReader, io.Closer, error)
  // Update updates key with value
  Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
  // Put updates the key with value and replaces the key if it exists
  Put(key, value interface{}) error
}

type ebpfMap struct {
  loadedMap *ebpf.Map
}

func (em *ebpfMap) Lookup(key, valueOut interface{}) error {
  return em.loadedMap.Lookup(key, valueOut)
}

func (em *ebpfMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
  return em.loadedMap.Update(key, value, flags)
}

func (em *ebpfMap) Put(key, value interface{}) error {
  return em.loadedMap.Update(key, value, ebpf.UpdateAny)
}

func (em *ebpfMap) NewReaderFromPerfEventMap() (EventsReader, io.Closer, error) {
  rd, err := perf.NewReader(em.loadedMap, os.Getpagesize())
  if err != nil {
    return nil, nil, err
  }

  return &eventsReader{rd}, rd, nil
}

func (em *ebpfMap) NewReaderFromPerfEventMapWithOptions() (EventsReader, io.Closer, error) {
  rd, err := perf.NewReader(em.loadedMap, os.Getpagesize())
  if err != nil {
    return nil, nil, err
  }

  return &eventsReader{rd}, rd, nil
}



// Program is an ebpf program
type Program interface {
  // AttachPerfEvent attaches a new tracepoint to the program
  AttachPerfEvent(tracepointID uint64) error
  // AttachSocketEvent attackes a new perf event to receive traffic
  AttachSocketEvent(ifaceName string, events Map) error
  // DetachSocketEvent clean up xdp
  DetachSocketEvent() error
}

type program struct {
  loadedProg *ebpf.Program
}

func (p *program) AttachSocketEvent(ifaceName string, events Map) error {
  // XdpAttachMode selects a way how XDP program will be attached to interface
  type XdpAttachMode int

  const (
    // XdpAttachModeNone stands for "best effort" - kernel automatically
    // selects best mode (would try Drv first, then fallback to Generic).
    // NOTE: Kernel will not fallback to Generic XDP if NIC driver failed
    //       to install XDP program.
    XdpAttachModeNone XdpAttachMode = 0
    // XdpAttachModeSkb is "generic", kernel mode, less performant comparing to native,
    // but does not requires driver support.
    XdpAttachModeSkb XdpAttachMode = (1 << 1)
    // XdpAttachModeDrv is native, driver mode (support from driver side required)
    XdpAttachModeDrv XdpAttachMode = (1 << 2)
    // XdpAttachModeHw suitable for NICs with hardware XDP support
    XdpAttachModeHw XdpAttachMode = (1 << 3)
  )

  // Lookup interface by given name, we need to extract iface index
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		// Most likely no such interface
		return fmt.Errorf("LinkByName() failed: %v", err)
	}

	// Attach program
	if err := netlink.LinkSetXdpFdWithFlags(link, p.loadedProg.FD(), int(XdpAttachModeSkb)); err != nil {
		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
	}

//  attr := unix.PerfEventAttr{
//        Type:        unix.PERF_TYPE_SOFTWARE,
//        Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
//        Sample_type: unix.PERF_SAMPLE_RAW,
//       Sample:      1,
//       Wakeup:      1,
//  }

//  for i := 0; i < 4; i++ {
//  pfd, err := unix.PerfEventOpen(&attr, -1, i, -1, 0)
//  if err != nil {
//      return fmt.Errorf("unable to open perf events: %v", err)
//  }
//  if err = events.Update(unsafe.Pointer(&i), unsafe.Pointer(&pfd), ebpf.UpdateAny); err != nil {
//      return err
//   }
//  if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_ENABLE, 0); errno != 0 {
//      return fmt.Errorf("unable to set up perf events: %v", error(errno))
//  }
// }
//  if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(p.loadedProg.FD())); errno != 0 {
//      return fmt.Errorf("unable to attach bpf program to perf events: %v", error(errno))
//  }
  return nil
}

func (p *program) DetachSocketEvent() error {
  return nil
//	if p.ifname == "" {
//		return errors.New("Program isn't attached")
//	}
//	// Lookup interface by given name, we need to extract iface index
//	link, err := netlink.LinkByName(p.ifname)
//	if err != nil {
//		// Most likely no such interface
//		return fmt.Errorf("LinkByName() failed: %v", err)
//	}
//
//	// Setting eBPF program with FD -1 actually removes it from interface
//	if err := netlink.LinkSetXdpFdWithFlags(link, -1, int(p.mode)); err != nil {
//		return fmt.Errorf("LinkSetXdpFd() failed: %v", err)
//	}
//	p.ifname = ""
//
//	return nil
}

func (p *program) AttachPerfEvent(tracepointID uint64) error {
  attr := unix.PerfEventAttr{
        Type:        unix.PERF_TYPE_TRACEPOINT,
        Config:      tracepointID,
        Sample_type: unix.PERF_SAMPLE_RAW,
        Sample:      1,
        Wakeup:      1,
  }

  pfd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
  if err != nil {
      return fmt.Errorf("unable to open perf events: %v", err)
  }
  if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_ENABLE, 0); errno != 0 {
      return fmt.Errorf("unable to set up perf events: %v", error(err))
  }
  if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(p.loadedProg.FD())); errno != 0 {
      return fmt.Errorf("unable to attach bpf program to perf events: %v", error(errno))
  }

  return nil
}

func (c *collection) LoadProgram(programName string) (Program, io.Closer, error) {
  loadedProg := c.coll.DetachProgram(programName)
  if loadedProg == nil {
    return nil, nil, fmt.Errorf("could not load program by name %s", programName)
  }

  return &program{loadedProg}, loadedProg, nil
}

func (c *collection) LoadMap(mapName string) (Map, io.Closer, error) {
  loadedMap := c.coll.DetachMap(mapName)
  if loadedMap == nil {
    return nil, nil, fmt.Errorf("could not load map of name %s", mapName)
  }

  return &ebpfMap{loadedMap}, loadedMap, nil
}

// NewCollection returns a new ebpf collection from an ELF
// ebpf program file
func NewCollection(objectFilename string) (Collection, error) {
  bytecode, err := ioutil.ReadFile(objectFilename)
  if err != nil {
    return nil, err
  }

  collSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bytecode))
  if err != nil {
    return nil, err
  }

  coll, err := ebpf.NewCollection(collSpec)
  if err != nil {
    return nil, err
  }

  return &collection{coll}, err
}

// Record represents a record read from a perf event reader
type Record interface {
  // ReadValue reads a value from the raw bytes read from the record
  // in little endian
  ReadValue(val interface{}) error
  // ReadValueAt is ReadValue but from a specific offset of the raw bytes
  // in the record onwards
  ReadValueAt(val interface{}, offset int) error
  // CPU returns the CPU number from where the record was read
  CPU() int
}

type record struct {
  perfRecord perf.Record
}

func (r *record) CPU() int {
  return r.perfRecord.CPU
}

func (r *record) ReadValue(val interface{}) error {
  return binary.Read(bytes.NewBuffer(r.perfRecord.RawSample), binary.LittleEndian, val)
}

func (r *record) ReadValueAt(val interface{}, offset int) error {
  if offset >= len(r.perfRecord.RawSample) {
    return fmt.Errorf("offset bigger than raw sample size")
  }
  return binary.Read(bytes.NewBuffer(r.perfRecord.RawSample[offset:]), binary.LittleEndian, val)
}

// EventsReader is an interface for reading events from a perf event array
type EventsReader interface {
  // Read blocks reading from a perf event reader, calling fn for every event received
  // Returns if ctx is cancelled or there was some error reading
  Read(ctx context.Context, fn func(Record) error)  error
}

type eventsReader struct {
  reader *perf.Reader
}

func (er *eventsReader) Read(ctx context.Context, fn func(record Record) error) error {
  for {
    select {
      case <-ctx.Done():
        break
      default:
    }

    r, err := er.reader.Read()
    if err != nil {
      if perf.IsClosed(err) {
        return nil
      }
      return err
    }

    if err = fn(&record{r}); err != nil {
      return err
    }
  }

  return nil
}

// RegisterUprobe register a function offset to the uprobe events on the system
// It takes the probe name as defined in the ebpf program, the binary path we want
// to register an event from, and the function within the binary we want to register.
// Returns the tracepoint id if successful
func RegisterUprobe(binaryPath, functionName string) (uint64, error) {
  // See https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt
  return registerUprobe("p", binaryPath, functionName)
}

// RegisterUretprobe register a function offset to the uretprobe events on the system
// It takes the probe name as defined in the ebpf program, the binary path we want
// to register an event from, and the function within the binary we want to register.
// Returns the tracepoint id if successful
func RegisterUretprobe(binaryPath, functionName string) (uint64, error) {
  // See https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt
  return registerUprobe("r", binaryPath, functionName)
}

func registerUprobe(probeType, binaryPath, functionName string) (uint64, error) {
  addr, err := getSymbolAddress(binaryPath, functionName)
  if err != nil {
    return 0, err
  }

  eventName := fmt.Sprintf("%s__%s_%x_gobpf_%d", probeType, safeEventName(binaryPath), addr, os.Getpid())

  return writeUprobeEvent(probeType, eventName, binaryPath, addr)
}

const tracepointPath = "/sys/kernel/debug/tracing/events/syscalls/%s/id"

// RegisterTracepoint register a syscall tracepoint so that events can be read
// from it every time it's called. Returns the tracepoint id on succcess
func RegisterTracepoint(functionName string) (uint64, error) {
  id, err := ioutil.ReadFile(fmt.Sprintf(tracepointPath, functionName))
	if err != nil {
		return 0, fmt.Errorf("failed to read tracepoint ID for %s: %v", functionName, err)
	}

  tid := strings.TrimSuffix(string(id), "\n")

	return strconv.ParseUint(tid, 10, 64)
}

const uprobeEventsFileName = "/sys/kernel/debug/tracing/uprobe_events"
const uprobePath = "/sys/kernel/debug/tracing/events/uprobes/%s/id"

func writeUprobeEvent(probeType, eventName, path string, offset uint64) (uint64, error) {
  f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
  if err != nil {
    return 0, fmt.Errorf("cannot open uprobe_events: %v", err)
  }
  defer f.Close()

  cmd := fmt.Sprintf("%s:%s %s:%#x\n", probeType, eventName, path, offset)

  if _, err = f.WriteString(cmd); err != nil {
    return 0, fmt.Errorf("cannot write %q to uprobe_events: %v", cmd, err)
  }

  uprobeIdBytes, err := ioutil.ReadFile(fmt.Sprintf(uprobePath, eventName))
  if err != nil {
    return 0, fmt.Errorf("cannot read uprobe id: %v", err)
  }

  uprobeId, err := strconv.ParseUint(strings.TrimSpace(string(uprobeIdBytes)), 10, 64)
  if err != nil {
    return 0, fmt.Errorf("invalid uprobe id: %v", err)
  }

  return uprobeId, nil
}

func safeEventName(event string) string {
  var safeEventRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

	return safeEventRegexp.ReplaceAllString(event, "_")
}

func getSymbolAddress(elfPath, symbolName string) (uint64, error) {
  binFile, err := elf.Open(elfPath)
  if err != nil {
    return 0, err
  }
  defer binFile.Close()

  imported, err := binFile.ImportedLibraries()
  if err != nil {
    return 0, err
  }
  fmt.Println(imported)

  libSyms, err := binFile.ImportedSymbols()
  if err != nil {
    return 0, err
  }
  fmt.Println(libSyms)

  syms, err := binFile.DynamicSymbols()
  if err != nil {
    return 0, err
  }

  for _, sym := range syms {
    if sym.Name == symbolName {
      return sym.Value, nil
    }
  }

  return 0, fmt.Errorf("the symbol %s was not found", symbolName)
}

