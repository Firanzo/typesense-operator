/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	_ "k8s.io/client-go/discovery"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	tsv1alpha1 "github.com/akyriako/typesense-operator/api/v1alpha1"
	"github.com/akyriako/typesense-operator/internal/cert"
	"github.com/akyriako/typesense-operator/internal/controller"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(gatewayv1.SchemeBuilder.AddToScheme(scheme))
	utilruntime.Must(gatewayv1beta1.SchemeBuilder.AddToScheme(scheme))
	utilruntime.Must(monitoringv1.AddToScheme(scheme))
	utilruntime.Must(discoveryv1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme

	utilruntime.Must(tsv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var watchNamespace string
	var watchCurrentNamespace bool
	var enableWebhook bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.StringVar(&watchNamespace, "watch-namespace", "",
		"Optional namespace to watch. If set, the operator is restricted to that namespace.")
	flag.BoolVar(&watchCurrentNamespace, "watch-current-namespace", false,
		"If set, the operator watches only the namespace where its Pod is running.")
	flag.BoolVar(&enableWebhook, "enable-webhook", true,
		"If set to true, the webhook server is enabled. Use --enable-webhook=false to disable it.")

	opts := zap.Options{
		Development:     true,
		TimeEncoder:     zapcore.ISO8601TimeEncoder,
		StacktraceLevel: zapcore.DPanicLevel,
	}

	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	watchNamespace = getWatchNamespace(watchNamespace, watchCurrentNamespace)
	if watchNamespace != "" {
		setupLog.Info("Enabling namespace-scoped mode", "watch-namespace", watchNamespace)
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog = ctrl.Log.WithName("setup")

	kubeConfig := ctrl.GetConfigOrDie()
	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		setupLog.Error(err, "unable to create kubernetes clientset")
		os.Exit(1)
	}

	// Get Context tied to OS signals (SIGTERM, SIGINT) early to pass to background workers
	ctx := ctrl.SetupSignalHandler()
	webhookCertPath = initWebhookCertificates(
		ctx, enableWebhook, webhookCertPath, webhookCertName, webhookCertKey, clientSet,
	)

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	var metricsCertWatcher *certwatcher.CertWatcher
	webhookCertWatcher, webhookTLSOpts := initWebhookCertWatcher(
		enableWebhook, webhookCertPath, webhookCertName, webhookCertKey, tlsOpts,
	)

	var webhookServer webhook.Server
	if enableWebhook {
		webhookServer = webhook.NewServer(webhook.Options{
			TLSOpts: webhookTLSOpts,
		})
	}

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		// TODO(user): TLSOpts is used to allow configuring the TLS config used for the server. If certificates are
		// not provided, self-signed certificates will be generated by default. This option is not recommended for
		// production environments as self-signed certificates do not offer the same level of trust and security
		// as certificates issued by a trusted Certificate Authority (CA). The primary risk is potentially allowing
		// unauthorized access to sensitive metrics data. Consider replacing with CertDir, CertName, and KeyName
		// to provide certificates, ensuring the server communicates using trusted and secure certificates.
		TLSOpts: tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(metricsCertPath, metricsCertName),
			filepath.Join(metricsCertPath, metricsCertKey),
		)
		if err != nil {
			setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	leaderElectionID := "9cf0818f.opentelekomcloud.com"
	if watchNamespace != "" {
		leaderElectionID = fmt.Sprintf("%s.%s", watchNamespace, leaderElectionID)
	}

	options := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       leaderElectionID,
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	}

	if enableWebhook {
		options.WebhookServer = webhookServer
	}

	if watchNamespace != "" {
		options.Cache = cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				watchNamespace: {},
			},
		}
	}

	mgr, err := ctrl.NewManager(kubeConfig, options)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// discoveryClient, err := discovery.NewDiscoveryClientForConfig(kubeConfig)
	// if err != nil {
	// setupLog.Error(err, "unable to create discovery client")
	// }

	if err = (&controller.TypesenseClusterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		//nolint:staticcheck // GetEventRecorderFor is deprecated but required for backward compatibility
		Recorder:        mgr.GetEventRecorderFor("typesensecluster-controller"),
		ClientSet:       clientSet,
		DiscoveryClient: clientSet.DiscoveryClient,
		Configuration:   mgr.GetConfig(),
		InCluster:       isInCluster(),
		HttpClient:      mgr.GetHTTPClient(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TypesenseCluster")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if enableWebhook {
		setupLog.Info("Setting up webhook for TypesenseCluster")
		if err = (&tsv1alpha1.TypesenseCluster{}).SetupWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "TypesenseCluster")
			os.Exit(1)
		}
	}

	if metricsCertWatcher != nil {
		setupLog.Info("Adding metrics certificate watcher to manager")
		if err := mgr.Add(metricsCertWatcher); err != nil {
			setupLog.Error(err, "Unable to add metrics certificate watcher to manager")
			os.Exit(1)
		}
	}

	if enableWebhook && webhookCertWatcher != nil {
		setupLog.Info("Adding webhook certificate watcher to manager")
		if err := mgr.Add(webhookCertWatcher); err != nil {
			setupLog.Error(err, "Unable to add webhook certificate watcher to manager")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func initWebhookCertificates(
	ctx context.Context, enableWebhook bool, certPath, certName, certKey string, clientSet *kubernetes.Clientset,
) string {
	if !enableWebhook {
		return certPath
	}

	// Automatically set the default webhook certificate path when running in-cluster
	if certPath == "" && isInCluster() {
		certPath = "/tmp/k8s-webhook-server/serving-certs"
	}

	// Generate and patch self-signed certificates dynamically
	if isInCluster() {
		setupLog.Info("Generating self-signed webhook certificates")
		if err := setupWebhookCertificates(ctx, clientSet, certPath, certName, certKey); err != nil {
			setupLog.Error(err, "failed to setup webhook certificates")
			os.Exit(1)
		}

		// Start background routine to automatically rotate certificates before they expire
		startCertificateRotation(ctx, clientSet, certPath, certName, certKey)
	}
	return certPath
}

func initWebhookCertWatcher(
	enableWebhook bool, certPath, certName, certKey string, tlsOpts []func(*tls.Config),
) (*certwatcher.CertWatcher, []func(*tls.Config)) {
	if !enableWebhook || len(certPath) == 0 {
		return nil, tlsOpts
	}
	setupLog.Info("Initializing webhook certificate watcher using provided certificates",
		"webhook-cert-path", certPath, "webhook-cert-name", certName, "webhook-cert-key", certKey)

	watcher, err := certwatcher.New(
		filepath.Join(certPath, certName),
		filepath.Join(certPath, certKey),
	)
	if err != nil {
		setupLog.Error(err, "Failed to initialize webhook certificate watcher")
		os.Exit(1)
	}

	tlsOpts = append(tlsOpts, func(config *tls.Config) {
		config.GetCertificate = watcher.GetCertificate
	})
	return watcher, tlsOpts
}

func isInCluster() bool {
	const (
		tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	)

	_, err := os.Stat(tokenFile)
	inCluster := err == nil
	if !inCluster {
		setupLog.V(1).Info("manager is running in out-of-cluster mode")
	}

	return inCluster
}

func getWatchNamespace(flagValue string, useCurrent bool) string {
	if !useCurrent {
		useCurrent = strings.EqualFold(strings.TrimSpace(os.Getenv("WATCH_CURRENT_NAMESPACE")), "true")
	}

	if useCurrent {
		namespaceFile := "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
		content, err := os.ReadFile(namespaceFile)
		if err != nil {
			setupLog.Error(err, "unable to read current namespace from service account")
			os.Exit(1)
		}
		return strings.TrimSpace(string(content))
	}

	if strings.TrimSpace(flagValue) == "" {
		flagValue = strings.TrimSpace(os.Getenv("WATCH_NAMESPACE"))
	}

	return strings.TrimSpace(flagValue)
}

func setupWebhookCertificates(
	ctx context.Context, clientSet *kubernetes.Clientset, certDir, certName, keyName string,
) error {
	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return fmt.Errorf("could not read namespace: %v", err)
	}
	namespace := strings.TrimSpace(string(ns))

	svcName := os.Getenv("WEBHOOK_SERVICE_NAME")
	if svcName == "" {
		svcName = "typesense-operator-webhook-service"
	}

	caPEM, certPEM, keyPEM, err := cert.GenerateWebhookCerts(svcName, namespace)
	if err != nil {
		return fmt.Errorf("failed to generate certs: %v", err)
	}

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert dir: %v", err)
	}

	certPath := filepath.Join(certDir, certName)
	if err := os.WriteFile(certPath+".tmp", certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write tmp cert: %v", err)
	}
	if err := os.Rename(certPath+".tmp", certPath); err != nil {
		return fmt.Errorf("failed to atomically rename cert: %v", err)
	}

	keyPath := filepath.Join(certDir, keyName)
	if err := os.WriteFile(keyPath+".tmp", keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write tmp key: %v", err)
	}
	if err := os.Rename(keyPath+".tmp", keyPath); err != nil {
		return fmt.Errorf("failed to atomically rename key: %v", err)
	}

	// Patch webhook config with retry logic
	for i := 0; i < 5; i++ {
		webhooks, err := clientSet.AdmissionregistrationV1().
			ValidatingWebhookConfigurations().
			List(ctx, metav1.ListOptions{})
		if err != nil {
			if k8serrors.IsForbidden(err) {
				setupLog.Info(
					"Warning: Insufficient permissions to list " +
						"ValidatingWebhookConfigurations. Skipping webhook certificate " +
						"injection (expected in gapped mode).",
				)
				return nil
			}
			return fmt.Errorf("failed to list ValidatingWebhookConfigurations: %v", err)
		}

		patched := false
		for _, wh := range webhooks.Items {
			updated := false
			for j, w := range wh.Webhooks {
				if w.ClientConfig.Service != nil &&
					w.ClientConfig.Service.Name == svcName &&
					w.ClientConfig.Service.Namespace == namespace {
					wh.Webhooks[j].ClientConfig.CABundle = caPEM
					updated = true
				}
			}
			if updated {
				whCopy := wh
				_, err = clientSet.AdmissionregistrationV1().
					ValidatingWebhookConfigurations().
					Update(ctx, &whCopy, metav1.UpdateOptions{})
				if err != nil {
					if k8serrors.IsForbidden(err) {
						setupLog.Info(
							"Warning: Insufficient permissions to update "+
								"ValidatingWebhookConfiguration. "+
								"Skipping injection.",
							"name", wh.Name,
						)
						return nil
					}
					return fmt.Errorf("failed to update ValidatingWebhookConfiguration %s: %v", wh.Name, err)
				}
				setupLog.Info("Successfully patched ValidatingWebhookConfiguration", "name", wh.Name)
				patched = true
			}
		}
		if patched {
			return nil
		}
		setupLog.Info("ValidatingWebhookConfiguration not found yet, retrying in 2 seconds...")
		time.Sleep(2 * time.Second)
	}

	setupLog.Info("Warning: No matching ValidatingWebhookConfiguration found to patch.")
	return nil
}

func startCertificateRotation(ctx context.Context, clientSet *kubernetes.Clientset, certDir, certName, keyName string) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				setupLog.Info("Stopping webhook certificate rotation routine")
				return
			case <-ticker.C:
				certPath := filepath.Join(certDir, certName)
				certPEM, err := os.ReadFile(certPath)
				if err != nil {
					continue
				}
				block, _ := pem.Decode(certPEM)
				if block == nil {
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}
				// Rotate if less than 30 days remaining
				if time.Until(cert.NotAfter) < 30*24*time.Hour {
					setupLog.Info("Webhook certificate is nearing expiration, rotating now...")
					_ = setupWebhookCertificates(ctx, clientSet, certDir, certName, keyName)
				}
			}
		}
	}()
}
