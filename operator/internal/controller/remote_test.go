package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

// ruleServer serves one policy file and can be switched to a failure mode.
type ruleServer struct {
	*httptest.Server
	body atomic.Value // string
	mode atomic.Value // "ok", "500", "badjson"
	hits atomic.Int32
	auth atomic.Value // last Authorization header
}

func newRuleServer(body string) *ruleServer {
	s := &ruleServer{}
	s.body.Store(body)
	s.mode.Store("ok")
	s.auth.Store("")
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.auth.Store(r.Header.Get("Authorization"))
		switch s.mode.Load().(string) {
		case "500":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "badjson":
			w.Header().Set("ETag", `"broken"`)
			_, _ = w.Write([]byte(`{"custom_regexes": [{"pattern": "("}]}`))
			return
		}
		sum := sha256.Sum256([]byte(s.body.Load().(string)))
		etag := `"` + hex.EncodeToString(sum[:4]) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(s.body.Load().(string)))
	}))
	return s
}

func remotePolicy(url string, interval int32) *corev1alpha1.PiiPolicy {
	return &corev1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "central", Namespace: "apps", Generation: 1, UID: "uid-r"},
		Spec: corev1alpha1.PiiPolicySpec{
			InjectionMode: "file",
			Salt:          "0123456789abcdef0123456789abcdef",
			SensitiveKeys: []string{"local-key"},
			RemoteConfig: &corev1alpha1.RemoteConfig{
				URL:             url,
				IntervalSeconds: interval,
				AllowInsecure:   true,
				HeaderSecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "rules-token"},
					Key:                  "authorization",
				},
			},
		},
	}
}

func tokenSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rules-token", Namespace: "apps"},
		Data:       map[string][]byte{"authorization": []byte("Bearer s3cret\n")},
	}
}

func getConfigMap(t *testing.T, ctx context.Context, r *PiiPolicyReconciler) *corev1.ConfigMap {
	t.Helper()
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: "pii-shield-policy-central", Namespace: "apps"}, cm); err != nil {
		t.Fatalf("expected the rendered ConfigMap: %v", err)
	}
	return cm
}

func TestReconcileRemoteRulesMergeKeepLastGoodAndRollBack(t *testing.T) {
	ctx := context.Background()
	srv := newRuleServer(`{"revision": "r1", "entropy_threshold": 4.4, "sensitive_keys": ["central-key"], "salt": "ignored"}`)
	defer srv.Close()

	scheme := newTestScheme(t)
	policy := remotePolicy(srv.URL+"/policy.json", 120)
	reconciler := newTestReconciler(t, scheme, policy, tokenSecret())
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}}

	// 1. First pull: remote rules merged under the local ones.
	res, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 120*time.Second {
		t.Errorf("RequeueAfter = %v, want the interval", res.RequeueAfter)
	}
	if srv.auth.Load().(string) != "Bearer s3cret" {
		t.Errorf("Authorization header = %q, want the trimmed Secret value", srv.auth.Load())
	}
	cm := getConfigMap(t, ctx, reconciler)
	file := cm.Data["policy.json"]
	for _, want := range []string{`"entropy_threshold": 4.4`, `"local-key"`, `"revision": "r1+1"`} {
		if !strings.Contains(file, want) {
			t.Errorf("merged file lacks %s:\n%s", want, file)
		}
	}
	for _, no := range []string{"central-key", "salt", "ignored", "0123456789abcdef"} {
		if strings.Contains(file, no) {
			t.Errorf("merged file must not carry %q:\n%s", no, file)
		}
	}
	if !strings.Contains(cm.Data["remote.json"], `"central-key"`) {
		t.Errorf("the remote file as fetched must be kept:\n%s", cm.Data["remote.json"])
	}
	if cm.Annotations["pii-shield.io/remote-etag"] == "" {
		t.Error("the ETag must be kept on the ConfigMap")
	}
	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	cond := meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced")
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "Synced" {
		t.Fatalf("RemoteSynced = %+v, want True/Synced", cond)
	}
	if !strings.Contains(cond.Message, "ignored keys in the remote file: salt") || !strings.Contains(cond.Message, "allowInsecure") {
		t.Errorf("message must name the ignored keys and the insecure transport: %q", cond.Message)
	}
	if got.Status.Remote == nil || got.Status.Remote.Revision != "r1" || got.Status.Remote.ETag == "" || got.Status.Remote.LastSyncTime == nil {
		t.Fatalf("status.remote = %+v", got.Status.Remote)
	}
	firstHash := got.Status.RenderedPolicyHash
	firstRV := cm.ResourceVersion

	// 2. Second pull: 304, nothing rewritten.
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile (304): %v", err)
	}
	cm = getConfigMap(t, ctx, reconciler)
	if cm.ResourceVersion != firstRV {
		t.Error("a 304 must not rewrite the ConfigMap")
	}
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if cond = meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced"); !strings.Contains(cond.Message, "unchanged (304)") {
		t.Errorf("message after 304 = %q", cond.Message)
	}

	// 3. Source down, local edit: the last good remote rules stay and the
	// edit applies on top of them.
	srv.mode.Store("500")
	got.Spec.CustomRegexList = []corev1alpha1.RegexRule{{Name: "tx", Pattern: `^TX-\d+$`}}
	got.Generation = 2
	if err := reconciler.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	res, err = reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile (500): %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Errorf("RequeueAfter after a failure = %v, want the retry cap", res.RequeueAfter)
	}
	cm = getConfigMap(t, ctx, reconciler)
	file = cm.Data["policy.json"]
	for _, want := range []string{`"entropy_threshold": 4.4`, `^TX-`, `"revision": "r1+2"`} {
		if !strings.Contains(file, want) {
			t.Errorf("after a failed pull the file must keep the remote rules and take the local edit, lacks %s:\n%s", want, file)
		}
	}
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	cond = meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced")
	if cond.Status != metav1.ConditionFalse || cond.Reason != "FetchFailed" || !strings.Contains(cond.Message, "HTTP 500") || !strings.Contains(cond.Message, "keeping the last good") {
		t.Errorf("RemoteSynced after 500 = %+v", cond)
	}
	if got.Status.Remote == nil || got.Status.Remote.Revision != "r1" {
		t.Errorf("status.remote must still describe the last good pull: %+v", got.Status.Remote)
	}

	// 4. Source serves an invalid file: rejected whole, last good kept.
	srv.mode.Store("badjson")
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile (bad json): %v", err)
	}
	cm = getConfigMap(t, ctx, reconciler)
	if !strings.Contains(cm.Data["policy.json"], `"entropy_threshold": 4.4`) || strings.Contains(cm.Data["remote.json"], `"("`) {
		t.Error("an invalid remote file must not replace the last good copy")
	}
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if cond = meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced"); cond.Reason != "InvalidRegex" {
		t.Errorf("reason = %s, want InvalidRegex (%s)", cond.Reason, cond.Message)
	}

	// 5. Source back with a new revision: applied.
	srv.mode.Store("ok")
	srv.body.Store(`{"revision": "r2", "entropy_threshold": 4.6}`)
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile (r2): %v", err)
	}
	cm = getConfigMap(t, ctx, reconciler)
	if !strings.Contains(cm.Data["policy.json"], `"entropy_threshold": 4.6`) || !strings.Contains(cm.Data["policy.json"], `"revision": "r2+2"`) {
		t.Errorf("the new remote file must be applied:\n%s", cm.Data["policy.json"])
	}
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if got.Status.RenderedPolicyHash == firstHash {
		t.Error("the rendered hash must change with the rules")
	}

	// 6. remoteConfig removed: back to the local policy alone.
	got.Spec.RemoteConfig = nil
	got.Generation = 3
	if err := reconciler.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	res, err = reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile (local): %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Error("without a remote source there is nothing to requeue")
	}
	cm = getConfigMap(t, ctx, reconciler)
	if _, ok := cm.Data["remote.json"]; ok {
		t.Error("remote.json must go with remoteConfig")
	}
	if _, ok := cm.Annotations["pii-shield.io/remote-etag"]; ok {
		t.Error("the ETag annotation must go with remoteConfig")
	}
	if strings.Contains(cm.Data["policy.json"], "entropy_threshold") || !strings.Contains(cm.Data["policy.json"], `"revision": "3"`) {
		t.Errorf("the file must be rendered from the local policy alone:\n%s", cm.Data["policy.json"])
	}
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced") != nil || got.Status.Remote != nil {
		t.Error("the remote condition and status must be cleared")
	}
}

func TestReconcileRemoteRulesFirstPullFailsRendersLocalOnly(t *testing.T) {
	ctx := context.Background()
	srv := newRuleServer(`{"entropy_threshold": 4.4}`)
	defer srv.Close()
	srv.mode.Store("500")

	scheme := newTestScheme(t)
	policy := remotePolicy(srv.URL, 0)
	policy.Spec.RemoteConfig.HeaderSecretRef = nil
	policy.Spec.RemoteConfig.IntervalSeconds = 0
	reconciler := newTestReconciler(t, scheme, policy)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}}

	res, err := reconciler.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Errorf("RequeueAfter = %v, want the retry cap for the default interval", res.RequeueAfter)
	}
	cm := getConfigMap(t, ctx, reconciler)
	if strings.Contains(cm.Data["policy.json"], "entropy_threshold") || !strings.Contains(cm.Data["policy.json"], `"local-key"`) {
		t.Errorf("with no remote copy yet the local policy alone is rendered:\n%s", cm.Data["policy.json"])
	}
	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	cond := meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced")
	if cond == nil || cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, "no remote rules received yet") {
		t.Errorf("RemoteSynced = %+v", cond)
	}
	if got.Status.Remote != nil {
		t.Error("status.remote must stay unset until a pull succeeds")
	}
	if meta.FindStatusCondition(got.Status.Conditions, "Rendered").Status != metav1.ConditionTrue {
		t.Error("the local rendering must still be reported as done")
	}
}

func TestReconcileRemoteRulesMissingSecretAndInsecureURL(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	policy := remotePolicy("http://rules.invalid/policy.json", 60)
	reconciler := newTestReconciler(t, scheme, policy) // no Secret
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}}

	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	cond := meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced")
	if cond == nil || cond.Reason != "SecretNotFound" || !strings.Contains(cond.Message, "rules-token") {
		t.Errorf("RemoteSynced = %+v, want SecretNotFound naming the Secret", cond)
	}

	got.Spec.RemoteConfig.HeaderSecretRef = nil
	got.Spec.RemoteConfig.AllowInsecure = false
	if err := reconciler.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got = fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if cond = meta.FindStatusCondition(got.Status.Conditions, "RemoteSynced"); cond.Reason != "InsecureURL" {
		t.Errorf("reason = %s, want InsecureURL (%s)", cond.Reason, cond.Message)
	}
}
