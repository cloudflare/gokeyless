//+build tools

// A dummy package for vendering needed tools.
package tools

import (
	_ "golang.org/x/lint/golint"
	_ "golang.org/x/tools/cmd/goimports"
)
