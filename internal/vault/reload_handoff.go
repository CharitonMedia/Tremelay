package vault

import "golang.org/x/crypto/nacl/box"

// dekHandoffInnerLen is nonce || AES-GCM ciphertext of the new DEK.
const dekHandoffInnerLen = nonceLen + keyLen + 16

// minDEKHandoffLen bounds the dek_handoff column a 3e binary may have left
// pending. Item 3g removed the handoff: nothing writes or opens one, and a
// later commit clears it, but an older vault must still read.
func minDEKHandoffLen() int {
	return box.AnonymousOverhead + dekHandoffInnerLen
}
