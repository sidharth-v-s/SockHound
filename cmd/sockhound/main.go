package main

import (
	"os"

	"github.com/zoro/sockhound/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:], app.DefaultIO()))
}
