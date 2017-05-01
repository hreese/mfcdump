package main

/* Useful references:
* http://www.nxp.com/documents/application_note/AN10927.pdf
* http://cache.nxp.com/documents/data_sheet/MF1S50YYX_V1.pdf
 */
import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

const (
	CT           = 0x88
	SectorHeader = "- [ Sector %2d ] - [ %s ] -\n"
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

func ManufacturerBlock(input [16]byte) string {
	var (
		uid []byte
		//uidlen uint
		mdoff uint
	)
	switch {
	case input[0] == CT && input[5] == CT:
		uid = []byte{input[1], input[2], input[3], input[6], input[7], input[8], input[10], input[11], input[12], input[13]}
		//uidlen = 10
		mdoff = 15
	case input[0] == CT:
		uid = []byte{input[1], input[2], input[3], input[5], input[6], input[7], input[8]}
		//uidlen = 7
		mdoff = 10
	default:
		uid = []byte{input[0], input[1], input[2], input[3]}
		//uidlen = 4
		mdoff = 5
	}
	return fmt.Sprintf("  UID: %s (% x)    Manufacturer Data: % x", big.NewInt(0).SetBytes(uid), uid, input[mdoff:])
}

func SectorTrailer(input [16]byte) string {
	var (
		keyA = input[:6]
		keyB = input[10:]
		//access = input[6:10] // don't care at the moment
	)
	return fmt.Sprintf("  Key A: % x\n  Key B: % x", keyA, keyB)

}

func SectorHeading(input [64]byte, number int, isZero bool) string {
	var (
		checksums []string
		block     = input[:]
	)

	// checksum sector minus manufacturer block and trailer
	if isZero {
		csum := md5.Sum(block[16:48])
		checksums = append(checksums, base64.StdEncoding.EncodeToString(csum[:]))
	}
	// checksum sector minus trailer
	csum := md5.Sum(block[0:48])
	checksums = append(checksums, base64.StdEncoding.EncodeToString(csum[:]))
	// checksum complete sector
	csum = md5.Sum(block)
	checksums = append(checksums, base64.StdEncoding.EncodeToString(csum[:]))
	return fmt.Sprintf(SectorHeader, number, strings.Join(checksums, " "))
}

func (m *MFCDump) Dump() {
	var (
		block   [64]byte
		mfb, st [16]byte
	)
	hexdump := strings.Split(hex.Dump(m.raw), "\n")
	// parse block 0
	copy(block[:], m.raw[0:64])
	fmt.Println(SectorHeading(block, 0, true))
	for i := 0; i < 4; i++ {
		fmt.Println(hexdump[i])
	}
	fmt.Println()
	copy(mfb[:], block[0:16])
	fmt.Println(ManufacturerBlock(mfb))
	fmt.Println()
	copy(st[:], block[3*16:4*16])
	fmt.Println(SectorTrailer(st))
	fmt.Println()

	// iterate over all blocks
	for blockIndex := 1; blockIndex < 16; blockIndex++ {
		copy(block[:], m.raw[blockIndex*64:(blockIndex+1)*64])
		if SkipEmpty && (bytes.Compare(block[:3*16], ZeroBlock) == 0 || bytes.Compare(block[:3*16], FullBlock) == 0) {
			continue
		}
		fmt.Println(SectorHeading(block, blockIndex, false))
		for i := 0; i < 4; i++ {
			fmt.Println(hexdump[i+blockIndex*4])
		}
		fmt.Println()
		copy(st[:], block[3*16:4*16])
		fmt.Println(SectorTrailer(st))
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
