package mfax

import "testing"

func TestNormalizeRecoveryCode(t *testing.T) {
	for in, want := range map[string]string{
		"abcd-efgh-jkmn-pqrs":   "abcdefghjkmnpqrs",
		" ABCD EFGH JKMN PQRS ": "abcdefghjkmnpqrs",
		"abcdefghjkmnpqrs":      "abcdefghjkmnpqrs",
		"0O1I-lL00-0000-0000":   "0011110000000000", // substitutions de Crockford
	} {
		if got, ok := normalizeRecoveryCode(in); !ok || got != want {
			t.Errorf("%q : %q %v, attendu %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abcd-efgh-jkmn", "abcd-efgh-jkmn-pqrs-t", "abcd-efgh-jkmn-pqru", "123456", "abcd_efgh_jkmn_pqrs"} {
		if got, ok := normalizeRecoveryCode(in); ok {
			t.Errorf("%q accepté : %q", in, got)
		}
	}
}

func TestRecoveryHashBoundToUser(t *testing.T) {
	if recoveryHash(1, "abcdefghjkmnpqrs") == recoveryHash(2, "abcdefghjkmnpqrs") {
		t.Fatal("même empreinte pour deux comptes")
	}
	if len(recoveryHash(1, "abcdefghjkmnpqrs")) != 64 {
		t.Fatal("empreinte SHA-256 hexadécimale attendue")
	}
}

func TestRandomRecoveryCodeAlphabet(t *testing.T) {
	seen := map[byte]bool{}
	for range 200 {
		c, err := randomRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := normalizeRecoveryCode(c); !ok || len(c) != recoveryCodeLen {
			t.Fatalf("code tiré invalide : %q", c)
		}
		for i := range len(c) {
			seen[c[i]] = true
		}
	}
	if len(seen) != len(recoveryAlphabet) {
		t.Errorf("%d symboles vus sur %d", len(seen), len(recoveryAlphabet))
	}
}
