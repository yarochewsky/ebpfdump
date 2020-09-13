package memdump

import (
	"fmt"
	"os"

	"io"

	"github.com/prometheus/procfs"
)

// NewMemoryDump returns a new MemoryDump instance for the pid
func NewMemoryDump(pid int) (MemoryDump, error) {
	memFile, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}

	return &memdump{
		pid:     pid,
		memFile: memFile,
	}, nil
}

// MemoryDump is an interface for dumping a live process' memory
type MemoryDump interface {
	// Dump dumps the process memory to filename
	Dump(filename string) error
}

type memdump struct {
	pid     int
	memFile *os.File
	outFile *os.File
}

func (m *memdump) Dump(filename string) error {
	outFile, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	m.outFile = outFile

	p, err := procfs.NewProc(m.pid)
	if err != nil {
		return err
	}

	stats, err := p.Stat()
	if err != nil {
		return err
	}

	fmt.Println(stats.Comm)

	maps, err := p.ProcMaps()
	if err != nil {
		return err
	}

	for _, memMap := range maps {
		//    if memMap.Perms.Read && memMap.Perms.Write && memMap.Pathname == "" {

		// fmt.Println(memMap.Pathname)
		if err = m.readSection(memMap.StartAddr, memMap.EndAddr); err != nil {
			// fmt.Println(err)
			//        return err
			continue
		}
		//}
	}

	return nil
}

func (m *memdump) readSection(startAddr, endAddr uintptr) error {
	if _, err := m.memFile.Seek(int64(startAddr), 0); err != nil {
		return err
	}
	chunk := make([]byte, endAddr-startAddr)
	read, err := io.ReadFull(m.memFile, chunk)
	if err != nil {
		return err
	}
	if read < len(chunk) {
		return fmt.Errorf("did not read full memory")
	}

	written, err := m.outFile.Write(chunk)
	if err != nil {
		return err
	}

	if written < len(chunk) {
		return fmt.Errorf("did not write full memory")
	}

	return nil
}
