package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/remoterules"
)

// signedServer serves /v1/acme/payments/policy.json and its .sig; the
// test swaps both at will, a 404 .sig when sig is empty.
type signedServer struct {
	*httptest.Server
	mu        sync.Mutex
	body, sig string
}

func (s *signedServer) set(body, sig string) { s.mu.Lock(); s.body, s.sig = body, sig; s.mu.Unlock() }

func newSignedServer() *signedServer {
	s := &signedServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, sig := s.body, s.sig
		s.mu.Unlock()
		switch r.URL.Path {
		case "/v1/acme/payments/policy.json":
			sum := sha256.Sum256([]byte(body))
			etag := `"` + hex.EncodeToString(sum[:4]) + `"`
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = w.Write([]byte(body))
		case "/v1/acme/payments/policy.json.sig":
			if sig == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	return s
}

// signFile signs body as the rule server would and returns the .sig body.
func signFile(priv ed25519.PrivateKey, set string, publication, revision int64, body string) string {
	sum := sha256.Sum256([]byte(body))
	text := fmt.Sprintf("pii-shield-policy-signature-v1\nset: %s\npublication: %d\nrevision: %d\nsha256: %s\n", set, publication, revision, hex.EncodeToString(sum[:]))
	pub := priv.Public().(ed25519.PublicKey)
	out, _ := json.Marshal(map[string]any{
		"set": set, "publication": publication, "revision": revision, "sha256": hex.EncodeToString(sum[:]),
		"keyId": remoterules.KeyID(pub), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(text))),
	})
	return string(out)
}

type sigHarness struct {
	t   *testing.T
	ctx context.Context
	r   *PiiPolicyReconciler
	req ctrl.Request
}

// reconcile runs one reconcile and returns the policy, its RemoteSynced
// condition and the rendered file.
func (h sigHarness) reconcile() (*corev1alpha1.PiiPolicy, *metav1.Condition, string) {
	h.t.Helper()
	if _, err := h.r.Reconcile(h.ctx, h.req); err != nil {
		h.t.Fatalf("Reconcile: %v", err)
	}
	got := fetchPolicy(h.t, h.ctx, h.r, h.req.Name, h.req.Namespace)
	return got, meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced"), getConfigMap(h.t, h.ctx, h.r).Data["policy.json"]
}

// expectRefused checks that a pull was refused for reason and that the
// rendered file still carries want, the last good rules.
func (h sigHarness) expectRefused(name, reason, want, unwanted string) {
	h.t.Helper()
	_, cond, file := h.reconcile()
	if cond.Status != metav1.ConditionFalse || cond.Reason != reason || !strings.Contains(cond.Message, "keeping the last good") {
		h.t.Errorf("%s: %+v", name, cond)
	}
	if !strings.Contains(file, want) || strings.Contains(file, unwanted) {
		h.t.Errorf("%s: the last good rules must stay:\n%s", name, file)
	}
}

func TestReconcileRemoteRulesSignatures(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	keyID := remoterules.KeyID(pub)

	srv := newSignedServer()
	defer srv.Close()
	v1 := `{"revision":"1","entropy_threshold":4.1}`
	v2 := `{"revision":"2","entropy_threshold":4.2}`
	srv.set(v1, signFile(priv, "acme/payments", 1, 1, v1))

	scheme := newTestScheme(t)
	policy := remotePolicy(srv.URL+"/v1/acme/payments/policy.json", 60)
	policy.Spec.RemoteConfig.Signature = &corev1alpha1.RemoteSignature{PublicKeys: []string{"ed25519:" + base64.StdEncoding.EncodeToString(pub)}}
	reconciler := newTestReconciler(t, scheme, policy, tokenSecret())
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}}
	h := sigHarness{t: t, ctx: ctx, r: reconciler, req: req}
	reconcile := h.reconcile

	// 1. A signed file from a trusted key is accepted and recorded.
	got, cond, file := reconcile()
	if cond.Status != metav1.ConditionTrue || !strings.Contains(cond.Message, "signed by key "+keyID+", publication 1") {
		t.Fatalf("signed pull: %+v", cond)
	}
	if got.Status.Remote.Publication != 1 || got.Status.Remote.SignedBy != keyID || !strings.Contains(file, `4.1`) {
		t.Errorf("status.remote %+v, file %s", got.Status.Remote, file)
	}
	cm := getConfigMap(t, ctx, reconciler)
	if cm.Annotations["pii-shield.io/remote-signed-by"] != keyID || cm.Annotations["pii-shield.io/remote-publication"] != "1" {
		t.Errorf("annotations %v", cm.Annotations)
	}

	// 2. Unchanged (304): no new signature needed, still synced.
	if _, cond, _ = reconcile(); cond.Status != metav1.ConditionTrue {
		t.Errorf("304: %+v", cond)
	}

	// 3. Each refusal keeps the last good, signed copy.
	for _, tc := range []struct {
		name, body, sig, reason string
	}{
		{"file changed under the old signature", v2, signFile(priv, "acme/payments", 1, 1, v1), remoterules.ReasonSignatureInvalid},
		{"signed for another set", v2, signFile(priv, "acme/other", 2, 2, v2), remoterules.ReasonSignatureInvalid},
		{"signed by an unknown key", v2, signFile(stranger, "acme/payments", 2, 2, v2), remoterules.ReasonSignatureUntrusted},
		{"no signature", v2, "", remoterules.ReasonSignatureMissing},
		{"garbage signature file", v2, "not json", remoterules.ReasonSignatureInvalid},
	} {
		srv.set(tc.body, tc.sig)
		h.expectRefused(tc.name, tc.reason, `4.1`, `4.2`)
	}

	// 4. Publication 3 is accepted; then the server replays publication 1.
	srv.set(v2, signFile(priv, "acme/payments", 3, 2, v2))
	if got, cond, file = reconcile(); cond.Status != metav1.ConditionTrue || got.Status.Remote.Publication != 3 || !strings.Contains(file, `4.2`) {
		t.Fatalf("publication 3: %+v %+v", cond, got.Status.Remote)
	}
	srv.set(v1, signFile(priv, "acme/payments", 1, 1, v1))
	h.expectRefused("replay", remoterules.ReasonSignatureReplayed, `4.2`, `4.1`)
	// A rollback is a new, higher publication of the old file.
	srv.set(v1, signFile(priv, "acme/payments", 4, 1, v1))
	if got, cond, file = reconcile(); cond.Status != metav1.ConditionTrue || got.Status.Remote.Publication != 4 || !strings.Contains(file, `4.1`) {
		t.Errorf("rollback as publication 4: %+v\n%s", cond, file)
	}

	// 5. A key dropped from the list stops counting: its copy is not kept,
	// and the file it signed is refused.
	got.Spec.RemoteConfig.Signature.PublicKeys = []string{"ed25519:" + base64.StdEncoding.EncodeToString(stranger.Public().(ed25519.PublicKey))}
	if err := reconciler.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, cond, file = reconcile(); cond.Reason != remoterules.ReasonSignatureUntrusted || !strings.Contains(cond.Message, "no remote rules received yet") || strings.Contains(file, `4.1`) {
		t.Errorf("after dropping the key: %+v\n%s", cond, file)
	}

	// 6. A broken key list is a configuration error.
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	got.Spec.RemoteConfig.Signature.PublicKeys = []string{"ssh-ed25519 AAAA"}
	if err := reconciler.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, cond, _ = reconcile(); cond.Reason != remoterules.ReasonSignatureConfig || got.Status.Remote != nil {
		t.Errorf("bad key list: %+v %+v", cond, got.Status.Remote)
	}
}

func TestReconcileRemoteRulesSignatureTurnedOnDropsUnsignedCopy(t *testing.T) {
	ctx := context.Background()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newSignedServer()
	defer srv.Close()
	srv.set(`{"revision":"1","entropy_threshold":4.7}`, "")

	scheme := newTestScheme(t)
	policy := remotePolicy(srv.URL+"/v1/acme/payments/policy.json", 60)
	reconciler := newTestReconciler(t, scheme, policy, tokenSecret())
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(getConfigMap(t, ctx, reconciler).Data["policy.json"], `4.7`) {
		t.Fatal("without signature checks the unsigned file is accepted")
	}

	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	got.Spec.RemoteConfig.Signature = &corev1alpha1.RemoteSignature{PublicKeys: []string{"ed25519:" + base64.StdEncoding.EncodeToString(pub)}}
	if err := reconciler.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	cond := meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced")
	if cond.Reason != remoterules.ReasonSignatureMissing || strings.Contains(getConfigMap(t, ctx, reconciler).Data["policy.json"], `4.7`) {
		t.Errorf("an unsigned copy must not survive turning signatures on: %+v", cond)
	}
}
