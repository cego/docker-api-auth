package internal

import (
	"fmt"
	"os"
)

func MustReturn[T any](obj T, err error) T {
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
	return obj
}

func MustNotFail(err error) {
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
