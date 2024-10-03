package k6ecdsa

import (
	"go.k6.io/k6/js/modules"
)

var crypto = &Crypto{}

func main() {
	modules.Register("k6/x/ecdsa", crypto)
}
