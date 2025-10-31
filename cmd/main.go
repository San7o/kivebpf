/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"strings"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	kivev1 "github.com/San7o/kivebpf/api/v1"
	kivev2alpha1 "github.com/San7o/kivebpf/api/v2alpha1"
	kivecerts "github.com/San7o/kivebpf/internal/certmanager"
	kive "github.com/San7o/kivebpf/internal/controller"
	kivecontainer "github.com/San7o/kivebpf/internal/controller/container"
	kivebpf "github.com/San7o/kivebpf/internal/controller/ebpf"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kivev2alpha1.AddToScheme(scheme))
	utilruntime.Must(kivev1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var kivePolicyProbeAddr string
	var kiveDataProbeAddr string
	var kivePodProbeAddr string
	var secureMetrics bool
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableHTTP2 bool
	var initWebhookCertsAndExit bool
	var initWebhookSvcName string
	var initWebhookSvcNamespace string
	var initWebhookCertOrgName string
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&kivePolicyProbeAddr, "kive-policy-health-probe-bind-address", ":8081", "The address the kive policy endpoint binds to.")
	flag.StringVar(&kiveDataProbeAddr, "kive-data-health-probe-bind-address", ":8082", "The address the probe endpoint binds to.")
	flag.StringVar(&kivePodProbeAddr, "kive-pod-health-probe-bind-address", ":8082", "The address the probe endpoint binds to.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", kivecerts.CertDirectory, "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", kivecerts.SecretKeyTLSCert, "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", kivecerts.SecretKeyTLSKey, "The name of the webhook key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&initWebhookCertsAndExit, "init-webhook-certs-and-exit", false,
		"Run in init container mode to generate TLS certificates and configure webhooks. Exits after completion.")
	flag.StringVar(&initWebhookSvcName, "init-webhook-svc-name", "kivebpf-webhook-service",
		"The name of the webhook service (used in init mode)")
	flag.StringVar(&initWebhookSvcNamespace, "init-webhook-svc-namespace", kivev2alpha1.Namespace,
		"The namespace where the webhook service is deployed (used in init mode)")
	flag.StringVar(&initWebhookCertOrgName, "init-webhook-cert-org-name", kivev2alpha1.GroupVersion.Group,
		"The organization name for the webhook certificates (used in init mode)")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Init container mode: generate certificates and configure webhooks, then exit
	// This is used when the manager is run as an init container (avoids having multiple container images)
	if initWebhookCertsAndExit {
		setupLog.Info("running in init container mode - initializing webhook certificates")
		if err := kivecerts.InitWebhookCertificates(initWebhookSvcName, initWebhookSvcNamespace, initWebhookCertOrgName); err != nil {
			setupLog.Error(err, "failed to initialize webhook certificates")
			os.Exit(1)
		}
		setupLog.Info("webhook certificates initialized successfully - init container exiting")
		os.Exit(0)
	}

	// Continue with normal controller startup
	setupLog.Info("starting in controller mode")

	kernelIDBytes, err := os.ReadFile(kive.KernelIDPath)
	if err != nil {
		setupLog.Error(err, "Cannot read kerrnel boot ID at"+kive.KernelIDPath)
		os.Exit(1)
	}
	kive.KernelID = string(kernelIDBytes)
	kive.KernelID = strings.TrimSpace(kive.KernelID)

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerablpe to the HTTP/2 Stream Cancellation and
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

	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		// Since certificates are (currently) not provided, self-signed
		// certificates will be generated by default. This option is not
		// recommended for production environments as self-signed
		// certificates do not offer the same level of trust and security
		// as certificates issued by a trusted Certificate Authority
		// (CA). The primary risk is potentially allowing unauthorized
		// access to sensitive metrics data.
		//
		// TLS is currently not supported so by default the the argument
		// "metrics-bind-address" is set to 0 to disable metrics
		// completely, until TLS is fully supported.
		TLSOpts: tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// Managers
	// Multiple managers are neded for each resource type since they
	// need to run different leader elections.

	// KiveData manager
	kiveDataMgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: kiveDataProbeAddr,
		LeaderElection:         true,
		LeaderElectionID:       kive.KernelID,
	})
	if err != nil {
		setupLog.Error(err, "unable to start kiveData manager")
		os.Exit(1)
	}

	// Kive manager
	kivePolicyMgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: kivePolicyProbeAddr,
	})
	if err != nil {
		setupLog.Error(err, "unable to start kive manager")
		os.Exit(1)
	}

	// Pod manager
	kivePodMgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: kivePodProbeAddr,
		LeaderElection:         true,
		LeaderElectionID:       "kive",
	})
	if err != nil {
		setupLog.Error(err, "unable to start kivePod manager")
		os.Exit(1)
	}

	if err = (&kive.KivePolicyReconciler{
		Client:         kivePolicyMgr.GetClient(),
		UncachedClient: kivePolicyMgr.GetAPIReader(),
		Scheme:         kivePolicyMgr.GetScheme(),
	}).SetupWithManager(kivePolicyMgr); err != nil {
		setupLog.Error(err, "unable to create KivePolicy controller", "controller", "KivePolicy")
		os.Exit(1)
	}

	if err = (&kive.KiveDataReconciler{
		Client:         kiveDataMgr.GetClient(),
		UncachedClient: kiveDataMgr.GetAPIReader(),
		Scheme:         kiveDataMgr.GetScheme(),
	}).SetupWithManager(kiveDataMgr); err != nil {
		setupLog.Error(err, "unable to create KiveData controller", "controller", "KiveData")
		os.Exit(1)
	}

	if err = (&kive.KivePodReconciler{
		Client:         kivePodMgr.GetClient(),
		UncachedClient: kivePodMgr.GetAPIReader(),
	}).SetupWithManager(kivePodMgr); err != nil {
		setupLog.Error(err, "unable to create KivePod controller", "controller", "KivePod")
		os.Exit(1)
	}

	err = ctrl.NewWebhookManagedBy(kivePodMgr).
		For(&kivev2alpha1.KivePolicy{}).
		Complete()
	if err != nil {
		setupLog.Error(err, "unable to start webhook of KivePolicy")
		os.Exit(1)
	}

	err = ctrl.NewWebhookManagedBy(kivePodMgr).
		For(&kivev2alpha1.KiveData{}).
		Complete()
	if err != nil {
		setupLog.Error(err, "unable to start webhook of KiveData")
		os.Exit(1)
	}

	// Mutate and Validate are not needed but are a good addition. They
	// will be supported in the future.
	if os.Getenv("ENABLE_WEBHOOKS") != "false" {
		// Using the pod manager for the webhook
		if err = (&kivev2alpha1.KivePolicy{}).SetupMutateWebhookWithManager(kivePodMgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "KivePolicyMutate")
			os.Exit(1)
		}
		if err = (&kivev2alpha1.KivePolicy{}).SetupValidateWebhookWithManager(kivePodMgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "KivePolicyValidate")
			os.Exit(1)
		}
		if err = (&kivev2alpha1.KiveData{}).SetupMutateWebhookWithManager(kivePodMgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "KiveDataMutate")
			os.Exit(1)
		}
		if err = (&kivev2alpha1.KiveData{}).SetupValidateWebhookWithManager(kivePodMgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "KiveDataValidate")
			os.Exit(1)
		}
	}

	// +kubebuilder:scaffold:builder

	if err := kivePolicyMgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := kivePolicyMgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	if err := kiveDataMgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := kiveDataMgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	if err := kivePodMgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := kivePodMgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting kive managers")

	go func() {
		if err := kivePolicyMgr.Start(context.Background()); err != nil {
			setupLog.Error(err, "Error running KivePolicy manager")
			os.Exit(1)
		}
	}()

	go func() {
		if err := kivePodMgr.Start(context.Background()); err != nil {
			setupLog.Error(err, "Error running KivePod manager")
			os.Exit(1)
		}
	}()

	kiveDataMgrCtx := ctrl.SetupSignalHandler()

	// Unload the eBPF program when leadership is lost
	go func() {
		<-kiveDataMgrCtx.Done() // Wait until leadership is lost
		setupLog.Info("KiveData manager lost leadership")

		kivebpf.UnloadEbpf(context.Background())
	}()

	if err := kiveDataMgr.Start(kiveDataMgrCtx); err != nil {
		setupLog.Error(err, "Error running KiveData manager")
		os.Exit(1)
	}

	// Cleanup
	if err := kivecontainer.CloseConnections(); err != nil {
		setupLog.Error(err, "Error closing connections")
	}
	if err := kivebpf.UnloadEbpf(context.Background()); err != nil {
		setupLog.Error(err, "Error unloading eBPF programs")
	}
}
