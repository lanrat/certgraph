package main

import (
	"fmt"
	"github.com/lanrat/certgraph/ct/google"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s example.com\n", os.Args[0])
		return
	}

	err := google.CTexample(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}
}
