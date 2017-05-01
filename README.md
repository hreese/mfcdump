# mfcdump
Display Mifare Classic dumps

## Installation

* [Install Go](https://golang.org/doc/install)
* `go get github.com/hreese/mfcdump`

## Usage

mfcdump reads and displays a single Mifare Classic dump. Input is read via stdin or filename. Use `-skipempty` to suppress sectors that only contain `0x00` or `0xff`.
