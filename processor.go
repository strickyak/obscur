package obscur

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"io"
	//"log"
	"regexp"
	"strconv"
	"strings"
)

type processor struct {
	encrypt       bool
	gcm           cipher.AEAD
	numLines      int
	matchPlain    *regexp.Regexp
	replacePlain  string
	matchCipher   *regexp.Regexp
	replaceCipher string
}

// obscur 1 {begin (.*) end} {beginx & endx} {beginx (.*) endx} {begin & end}

var MatchObscur = regexp.MustCompile(`obscur ([0-9]+) {(.+?)} {(.*?<@>.*?)} {(.+?)} {(.*?<@>.*?)}`).FindStringSubmatch

func NewProcessor(encrypt bool, key string) *processor {
	p := &processor{
		encrypt: encrypt,
	}
	hash := sha512.Sum512([]byte(key))
	key2 := make([]byte, aes.BlockSize)
	for i, x := range hash {
		key2[i%aes.BlockSize] ^= x
	}
	block, err := aes.NewCipher(key2)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	p.gcm = gcm
	return p
}

func (p *processor) ProcessStream(r io.Reader, w io.Writer) {
	r2 := bufio.NewReader(r)
	w2 := bufio.NewWriter(w)
	for {
		s, err := r2.ReadString('\n')
		if s != "" || err == nil {
			s2 := p.ProcessLine(s)
			_, err = w2.WriteString(s2)
			if err != nil {
				panic(err)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
	}
	w2.Flush()
}

func (p *processor) ProcessLine(s string) string {
	// A new obscur declaration replaces any old one.
	mo := MatchObscur(s)
	if len(mo) == 6 {
		// Found an obscur line.
		n, err := strconv.Atoi(mo[1])
		if err != nil {
			panic(err)
		}
		// Replace the former obscur pattern.
		p.numLines = n
		p.matchPlain = regexp.MustCompile(mo[2])
		p.replacePlain = mo[3]
		p.matchCipher = regexp.MustCompile(mo[4])
		p.replaceCipher = mo[5]
		return s
	}

	if p.matchPlain == nil {
		return s // No encryption right now.
	}
	if p.matchCipher == nil {
		panic("impossible")
	}

	// func (re *Regexp) ExpandString(dst []byte, template string, src string, match []int) []byte

	// func (re *Regexp) ReplaceAllFunc(src []byte, repl func([]byte) []byte) []byte

	if p.encrypt {
		s = p.matchPlain.ReplaceAllStringFunc(s, func(m string) string {
			ms := p.matchPlain.FindStringSubmatch(s)
			if len(ms) != 2 {
				panic("p.matchPlain.FindStringSubmatch")
			}
			z := p.EncryptString(ms[1])
			return strings.Replace(p.replacePlain, "<@>", z, 1)
		})
	} else {
		s = p.matchCipher.ReplaceAllStringFunc(s, func(m string) string {
			ms := p.matchCipher.FindStringSubmatch(s)
			if len(ms) != 2 {
				panic("p.matchCipher.FindStringSubmatch")
			}
			z := p.DecryptString(ms[1])
			return strings.Replace(p.replaceCipher, "<@>", z, 1)
		})
	}

	if p.numLines > 0 {
		p.numLines--
		if p.numLines == 0 {
			p.matchPlain = nil
			p.matchCipher = nil
		}
	}
	return s
}

func ParanoidNonceCheck(nonce []byte) bool {
	// Make sure the random didn't totally fail.
	// We check no bytes are repeated.
	// With a 12 byte nonce, and 256 possible bytes,
	// this discards too small a portion of the nonce space
	// to be significant in reducing security.

	// Fix this if hell freezes over.
	if len(nonce) != 12 {
		return false
	}

	// O(n*2) is small because n==12.
	for i := 0; i < len(nonce); i++ {
		for j := i + 1; j < len(nonce); j++ {
			if nonce[i] == nonce[j] {
				return false
			}
		}
	}
	return true
}

func (p *processor) EncryptString(s string) string {
	var nonce []byte
	for {
		nonce = make([]byte, p.gcm.NonceSize())
		cc, err := rand.Read(nonce)
		if err != nil {
			panic(err)
		}
		if cc != p.gcm.NonceSize() {
			panic("impossible")
		}
		if ParanoidNonceCheck(nonce) {
			break
		}
	}
	// Seal(dst, nonce, plaintext, additionalData []byte) []byte
	z := p.gcm.Seal(nil, nonce, []byte(s), nil)
	//log.Printf("EncryptString3 z: %q", string(z))
	z2 := append(z, nonce...) // The last 12 bytes of encoded bytes will be the nonce.
	//log.Printf("EncryptString4 z2: %q", string(z2))
	z3 := base64.RawURLEncoding.EncodeToString(z2)
	//log.Printf("EncryptString5 z3: %q", string(z3))
	return z3
}

func (p *processor) DecryptString(s string) string {
	//log.Printf("DecryptString: %q", s)
	bb, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	//log.Printf("DecryptString2: %q", string(bb))
	n := len(bb)
	// The last 12 bytes of encoded bytes will be the nonce.
	sep := n - p.gcm.NonceSize()
	nonce := bb[sep:n]

	// Paranoid checks should still pass.
	if !ParanoidNonceCheck(nonce) {
		panic("corrupted nonce")
	}

	// Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	//log.Printf("DecryptString3: %q", string(bb[:sep]))
	z, err := p.gcm.Open(nil, nonce, bb[:sep], nil)
	if err != nil {
		panic(err)
	}
	return string(z)
}
