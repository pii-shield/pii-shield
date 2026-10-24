package scanner

import (
	"strings"
	"testing"
)

// TestIndexNameAfterBareKeyKept: in prose, "key" is how a database names an
// index or a constraint, and the bare word forced the token after it, so the
// index name in every MySQL duplicate-key error was hidden: "Duplicate entry
// 'x' for key 'users.email'" came back as "for key '[HIDDEN:...]'". Found
// while fixing the dump row of elan-registry/registry#2256 (leak-radar
// complaints 2026-09-30). A name that reads as a compound of words is scored
// on its own now.
func TestIndexNameAfterBareKeyKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		`Duplicate entry 'x' for key 'users.email'`,
		`{"error": "Duplicate entry 'x' for key 'users.email'"}`,
		`SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry '42-7' for key 'order_items.PRIMARY'`,
		`ERROR 1062 (23000): Duplicate entry 'x' for key 'idx_user_email'`,
		`Duplicate entry '606-14' for key 'order_items.email'`,
		`Duplicate entry \'x\' for key \'users.email\'`,
		`ALTER TABLE t ADD KEY idx_order_id (order_id);`,
		`ALTER TABLE t ADD UNIQUE KEY uq_users_email (email);`,
		`the key rotation_job.daily ran`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("index name hidden:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestBareKeyStillForcesSecrets: the relaxation is for word compounds after
// the bare word key only. A random token, a signature, a compound that names
// a secret, a value after key: or key=, and a value after a strong secret
// word keep the force.
func TestBareKeyStillForcesSecrets(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret string }{
		{"key Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz", "Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz"},
		{"key Xk9_Qp2Lm7_Zt4Rw8", "Xk9_Qp2Lm7_Zt4Rw8"},
		{"key 'k3j9x2ab_qz7vwm1p'", "k3j9x2ab_qz7vwm1p"},
		{"key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
		{"key: users.email", "users.email"},
		{"key=users.email", "users.email"},
		{"password users.email", "users.email"},
		{"token user_service.prod", "user_service.prod"},
	} {
		if out := ScanAndRedact(tc.in); strings.Contains(out, tc.secret) {
			t.Errorf("value after a key no longer hidden: %q -> %q", tc.in, out)
		}
	}
}

func TestIsIdentifierName(t *testing.T) {
	st := cfgState()
	for _, s := range []string{"users.email", "order_items.email", "order_items.PRIMARY", "idx_user_email", "uq_users_email", "orders.user_id2", "audit_log.created_at"} {
		if !st.isIdentifierName(s) {
			t.Errorf("isIdentifierName(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"users", "api_key", "auth_token.value", "Xk9_Qp2Lm7_Zt4Rw8", "k3j9x2ab_qz7vwm1p", "abcd-efgh-ijkl",
		"a.b", "users..email", "users.", "x_y", "qzxv_kjwp_mmrt", "users/email", "",
	} {
		if st.isIdentifierName(s) {
			t.Errorf("isIdentifierName(%q) = true, want false", s)
		}
	}
}
