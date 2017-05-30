package obscur_test

import . "github.com/strickyak/obscur"

import (
	"testing"
)

var s1 = []string{
	"",
	"mumble",
	"frodo obscur 4 {a(.*)b} {A<@>B} {A(.*)B} {a<@>b}",
	"# aFoob",
	"# aZoob",
	"# aMoob",
	"# aDewb",
	"- aStewb",
	"zumble",
}

func TestParanoidNonceCheck(t *testing.T) {
	if !ParanoidNonceCheck([]byte("abcdefghijkl")) {
		t.Errorf("ParanoidNonceCheck bad abcdefghijkl")
	}
	if ParanoidNonceCheck([]byte("abcdefghijkg")) {
		t.Errorf("ParanoidNonceCheck bad abcdefghijkg")
	}
	if ParanoidNonceCheck([]byte("abcdefghijk")) {
		t.Errorf("ParanoidNonceCheck bad eleven")
	}
	if ParanoidNonceCheck([]byte("\000\000\000\000\000\000\000\000\000\000\000\000")) {
		t.Errorf("ParanoidNonceCheck bad eggs")
	}
	if ParanoidNonceCheck([]byte("")) {
		t.Errorf("ParanoidNonceCheck bad empty")
	}
}

func TestProcessline(t *testing.T) {
	encr := NewProcessor(true, "key")
	decr := NewProcessor(false, "key")

	for _, s := range s1 {
		println("s:", s)
		x := encr.ProcessLine(s)

		if len(s) > 0 && s[0] == '#' {
			if s == x {
				t.Errorf("%q == %q", s, x)
			}
		} else {
			if s != x {
				t.Errorf("%q != %q", s, x)
			}
		}

		println("x:", x)
		z := decr.ProcessLine(x)
		println("z:", z)
		println("")

		if s != z {
			t.Errorf("%q != %q", s, z)
		}
	}
}

func TestEncryptString(t *testing.T) {
	e1 := NewProcessor(true, "password")
	d1 := NewProcessor(false, "password")
	e2 := NewProcessor(true, "password!")
	d2 := NewProcessor(false, "password!")

	q1 := e1.EncryptString("foobar")
	q2 := e2.EncryptString("foobar")
	qq1 := d1.DecryptString(q1)
	qq2 := d2.DecryptString(q2)

	if qq1 != "foobar" {
		t.Errorf("qq1 : %q", qq1)
	}
	if qq2 != "foobar" {
		t.Errorf("qq2 : %q", qq2)
	}
	if q1 == "foobar" {
		t.Errorf("q1 : %q", qq1)
	}
	if q2 == "foobar" {
		t.Errorf("q2 : %q", qq2)
	}
	if q1 == q2 {
		t.Errorf("q1 q2 : %q %q", q1, q2)
	}
}
