package main

/* Useful references:
* http://www.nxp.com/documents/application_note/AN10927.pdf
* http://cache.nxp.com/documents/data_sheet/MF1S50YYX_V1.pdf
 */
import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	CT           = 0x88
	SectorHeader = "---------- [ Sector %2d ] ----------\n"
)

var (
	ZeroBlock    = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	FullBlock    = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	SkipEmpty    bool
	HexSeparator string = " "
)

type MFCDump struct {
	raw []byte
}

func HexBytes(input []byte, delim string) string {
	hexbytes := make([]string, len(input))
	for idx, b := range input {
		hexbytes[idx] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(hexbytes, delim)
}

func NewMFCDump(input []byte) (MFCDump, error) {
	// check length
	switch {
	case len(input) < 1024:
		return MFCDump{}, errors.New("input is too small to be a Mifare Classic dump")
	case len(input) > 1024:
		return MFCDump{}, errors.New("input is too large to be a Mifare Classic dump")
	}
	return MFCDump{raw: input[:]}, nil
}

// XXX: len(16)
func ManufacturerBlock(input []byte) string {
	var (
		uid    []byte
		uidlen uint
		mdoff  uint
	)
	switch {
	case input[0] == CT && input[5] == CT:
		uid = []byte{input[1], input[2], input[3], input[6], input[7], input[8], input[10], input[11], input[12], input[13]}
		uidlen = 10
		mdoff = 15
	case input[0] == CT:
		uid = []byte{input[1], input[2], input[3], input[5], input[6], input[7], input[8]}
		uidlen = 7
		mdoff = 10
	default:
		uid = []byte{input[0], input[1], input[2], input[3]}
		uidlen = 4
		mdoff = 5
	}
	return fmt.Sprintf("  UID (%2d bytes): %s    Manufacturer Data: %s", uidlen, HexBytes(uid, HexSeparator), HexBytes(input[mdoff:], HexSeparator))
}

// XXX: len(16)
func SectorTrailer(input []byte) string {
	var (
		keyA   = input[:6]
		keyB   = input[10:]
		access = input[6:10]
	)
	// yes, I currently do not care for access bits :-)
	return fmt.Sprintf("  Key A: %s    Key B: %s    Access bits: %s", HexBytes(keyA, HexSeparator), HexBytes(keyB, HexSeparator), HexBytes(access, HexSeparator))
}

func (m *MFCDump) Dump() {
	var (
		block []byte
	)
	hexdump := strings.Split(hex.Dump(m.raw), "\n")
	// parse block 0
	fmt.Printf(SectorHeader, 0)
	block = m.raw[0:64]
	for i := 0; i < 4; i++ {
		fmt.Println(hexdump[i])
	}
	fmt.Println()
	fmt.Println(ManufacturerBlock(block[0:16]))
	fmt.Println()
	fmt.Println(SectorTrailer(block[3*16 : 4*16]))
	fmt.Println()

	// iterate over all blocks
	for blockIndex := 1; blockIndex < 16; blockIndex++ {
		block = m.raw[blockIndex*64 : (blockIndex+1)*64]
		if SkipEmpty && (bytes.Compare(block[:3*16], ZeroBlock) == 0 || bytes.Compare(block[:3*16], FullBlock) == 0) {
			continue
		}
		fmt.Printf(SectorHeader, blockIndex)
		for i := 0; i < 4; i++ {
			fmt.Println(hexdump[i+blockIndex*4])
		}
		fmt.Println()
		fmt.Println(SectorTrailer(block[3*16 : 4*16]))
		fmt.Println()
	}
}

func init() {
	flag.BoolVar(&SkipEmpty, "skipempty", false, "Skip sectors that consist of 0x00 or 0xff.")
	flag.Parse()
}

func main() {
	var (
		input []byte
		err   error
	)

	switch {
	// stdin
	case flag.NArg() == 0 || (flag.NArg() == 1 && flag.Args()[0] == "-"):
		input, err = ioutil.ReadAll(bufio.NewReader(os.Stdin))
	case flag.NArg() == 1:
		input, err = ioutil.ReadFile(flag.Args()[0])
	default:
		err = errors.New("Only one file plz.")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}
	mfc, err := NewMFCDump(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}
	mfc.Dump()
}
