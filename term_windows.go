// +build windows

package ssh

import (
	"golang.org/x/crypto/ssh"
)

// monWinCh does nothing for windows
func monWinCh(session *ssh.Session, fd uintptr) {
}
