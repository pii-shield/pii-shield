package scanner

import (
	"strings"
	"testing"
)

// Real public-key bodies, generated with ssh-keygen. Public keys are not
// secrets; they are here because the whitelist exists to keep exactly these
// readable in logs.
const (
	sshEd25519Body = "AAAAC3NzaC1lZDI1NTE5AAAAIFGppB2LwjAd5WSWy70PBsnMUUAVOBDiptPw/OWbBH1q"
	sshRSABody     = "AAAAB3NzaC1yc2EAAAADAQABAAABAQCTEXytnoHllhkixenvpbfDrFsmrOGvj1CL3o61etpemU03tz5nAG5p1AvrZQpastkRbL5MRg1/ZrKZCXhBVk9JNyphgul5g1V5pixAHtrUe/ugedc6Zj0p3GQnunZhdPsKh9b9bkI9hiaI6CdnhPuUHfHccqx9xK04wr53ajYOdegMk0g1PTKyjzzDVwT30m61ffzWItvimUBGjY6lV0lPIkZE2+NNNcY7nlwm477Q6PyU4iDPk7K6Pdh6fHCXFyHUlMJ2rKgTTGCYd+RPtfH/uVy0YIe7UfQG0Qr++VZH4oPI8b9DTt21Ks+y4TSMyK9hZtYaKSmmv/siVikHytux"
	sshECDSABody   = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOrhaxYFOK2bvFDwBVzKRUOPiv74tMhtybVObo/vPw9ppnVr0v4q31hwWdQn6xw0/1Aml4AWnrFTTXvG16xBPTE="
)

// TestSSHKeyBodyWhitelistNarrowed covers F2. The whitelist used to accept any
// base64-looking token that started with AAAA and was longer than 20 bytes —
// three zero bytes were enough to walk a high-entropy blob straight past the
// scorer. The body of a real SSH public key encodes its own algorithm name in
// the first wire-format field, so that name is what the whitelist now asks for.
//
// This is a structural check, not the line-context gating the campaign notes
// sketched: it needs no neighbouring token, so it also holds for a key body
// that arrives on a line of its own.
func TestSSHKeyBodyWhitelistNarrowed(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// Real public keys stay readable, with and without the algorithm prefix.
	for _, line := range []string{
		"ssh-ed25519 " + sshEd25519Body,
		"ssh-rsa " + sshRSABody,
		sshEd25519Body,
		sshRSABody,
		sshECDSABody,
	} {
		if out := ScanAndRedact(line); !strings.Contains(out, "AAAA") {
			t.Errorf("real ssh public key redacted: %q -> %q", line, out)
		}
	}

	// A high-entropy blob that merely starts with AAAA is not a key body.
	// Verified leaking on main: this exact token came back unchanged.
	const blob = "AAAAQRqo9wWUlWDPuDzEFiuw+t6zLUPTntzWnxmsYTlIdEtosJ+asP01xw4Q8mMJ"
	if out := ScanAndRedact(blob); strings.Contains(out, blob) {
		t.Errorf("high-entropy AAAA blob still whitelisted: %q", out)
	}
	if out := ScanAndRedact("payload " + blob + " end"); strings.Contains(out, blob) {
		t.Errorf("high-entropy AAAA blob still whitelisted in context: %q", out)
	}

	// Regression: a keyed value was never whitelisted and must stay redacted.
	const hash40 = "9c1185a5c5e9fc54612808977ee8f548b2258d31"
	if out := ScanAndRedact("api_token=" + hash40); strings.Contains(out, hash40) {
		t.Errorf("keyed 40-hex value leaked: %q", out)
	}

	// The matcher itself.
	for _, tc := range []struct {
		token string
		want  bool
	}{
		{sshEd25519Body, true},
		{sshRSABody, true},
		{sshECDSABody, true},
		{blob, false},
		{"AAAA", false},
		{"AAAAB3NzaC1yc2E", false},                    // right shape, too short
		{"AAAA!!!!" + strings.Repeat("a", 30), false}, // not base64
		{strings.Repeat("A", 64), false},              // decodes to zeros: no name
		{"BBBB" + strings.Repeat("a", 40), false},     // wrong prefix
	} {
		if got := isSSHKeyBody(tc.token); got != tc.want {
			t.Errorf("isSSHKeyBody(%.24q...) = %v, want %v", tc.token, got, tc.want)
		}
	}
}
