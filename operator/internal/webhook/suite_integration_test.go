//go:build integration

package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/controller"
)

// This suite runs the mutating webhook the way a cluster does: a real
// kube-apiserver (envtest) loads the MutatingWebhookConfiguration from
// config/webhook and calls the handler over TLS for every pod it is asked to
// create or update. The unit tests call Handle directly and look at the patch;
// only here does the API server apply that patch and validate the result, so
// only here does a patch the server would refuse show up as a failure. The
// PiiPolicy controller runs next to the webhook, as in the operator, so the
// rendered policy ConfigMap is the real one.

var (
	integrationCancel context.CancelFunc
	testEnv           *envtest.Environment
	cfg               *rest.Config
	k8sClient         client.Client
	// warnings collects the admission warnings the API server returned to
	// k8sClient, in order.
	warnings *warningRecorder
)

type warningRecorder struct{ got chan string }

func (w *warningRecorder) HandleWarningHeader(_ int, _ string, text string) {
	select {
	case w.got <- text:
	default:
	}
}

// drain returns the warnings received since the last call.
func (w *warningRecorder) drain() []string {
	var out []string
	for {
		select {
		case s := <-w.got:
			out = append(out, s)
		default:
			return out
		}
	}
}

func TestWebhookIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Webhook Integration Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	var ctx context.Context
	ctx, integrationCancel = context.WithCancel(context.TODO())

	Expect(piishieldv1alpha1.AddToScheme(scheme.Scheme)).To(Succeed())

	By("bootstrapping envtest with the webhook configuration from config/webhook")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("..", "..", "config", "webhook", "manifests.yaml")},
		},
	}
	if dir := firstEnvTestBinaryDir(); dir != "" {
		testEnv.BinaryAssetsDirectory = dir
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())

	warnings = &warningRecorder{got: make(chan string, 64)}
	clientCfg := rest.CopyConfig(cfg)
	clientCfg.WarningHandler = warnings
	k8sClient, err = client.New(clientCfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())

	By("starting the manager with the PiiPolicy controller and the pod webhook")
	opts := &testEnv.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme.Scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Host: opts.LocalServingHost, Port: opts.LocalServingPort, CertDir: opts.LocalServingCertDir,
		}),
	})
	Expect(err).NotTo(HaveOccurred())
	Expect((&controller.PiiPolicyReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(), APIReader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr)).To(Succeed())
	// Registered exactly as cmd/main.go does it.
	mgr.GetWebhookServer().Register("/mutate-v1-pod", &ctrlwebhook.Admission{
		Handler: &PodMutator{Client: mgr.GetClient(), Decoder: admission.NewDecoder(mgr.GetScheme())},
	})
	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()

	By("waiting for the webhook server to accept TLS connections")
	addr := net.JoinHostPort(opts.LocalServingHost, fmt.Sprint(opts.LocalServingPort))
	Eventually(func() error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // local test server
		if err != nil {
			return err
		}
		return conn.Close()
	}, 30*time.Second, 200*time.Millisecond).Should(Succeed())
})

var _ = AfterSuite(func() {
	By("tearing down the manager and envtest")
	integrationCancel()
	Eventually(func() error { return testEnv.Stop() }, time.Minute, time.Second).Should(Succeed())
})

func firstEnvTestBinaryDir() string {
	base := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join(base, e.Name())
		}
	}
	return ""
}
