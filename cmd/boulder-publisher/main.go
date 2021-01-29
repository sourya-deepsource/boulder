package main

import (
	"flag"
	"os"
	"runtime"

	ct "github.com/google/certificate-transparency-go"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/publisher"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
)

type config struct {
	Publisher struct {
		cmd.ServiceConfig
		Features map[string]bool

		// If this is non-zero, profile blocking events such that one even is
		// sampled every N nanoseconds.
		// https://golang.org/pkg/runtime/#SetBlockProfileRate
		BlockProfileRate int
		UserAgent        string

		// Chains is a list of lists of certificate filenames. Each inner list is
		// a chain (starting with the issuing intermediate, followed by one or
		// more additional certificates, up to and including a root) which we are
		// willing to serve. Chains that start with a given intermediate will only
		// be offered for certificates which were issued by the key pair represented
		// by that intermediate. The first chain representing any given issuing
		// key pair will be the default for that issuer, served if the client does
		// not request a specific chain.
		Chains [][]string
	}

	Syslog cmd.SyslogConfig

	// TODO(5164): Remove this after all configs have migrated to `Chains`.
	Common struct {
		CT struct {
			IntermediateBundleFilename string
		}
	}
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Publisher.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	runtime.SetBlockProfileRate(c.Publisher.BlockProfileRate)

	if *grpcAddr != "" {
		c.Publisher.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.Publisher.DebugAddr = *debugAddr
	}
	if c.Publisher.UserAgent == "" {
		c.Publisher.UserAgent = "certificate-transparency-go/1.0"
	}

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.Publisher.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// TODO(5164): Refactor this after all configs have migrated to `Chains`.
	if c.Common.CT.IntermediateBundleFilename == "" && c.Publisher.Chains == nil {
		logger.AuditErr("No CT submission bundle or chains provided")
		os.Exit(1)
	}

	bundle := []ct.ASN1Cert{}
	bundles := map[issuance.IssuerNameID][]ct.ASN1Cert{}
	if c.Publisher.Chains != nil {
		for _, files := range c.Publisher.Chains {
			issuer, _, bundle, err := issuance.LoadChain(files)
			cmd.FailOnError(err, "Failed to load chain")

			id := issuer.NameID()
			bundles[id] = bundle
		}

	} else {
		// TODO(5164): Remove this after all configs have migrated to `Chains`.
		pemBundle, err := core.LoadCertBundle(c.Common.CT.IntermediateBundleFilename)
		cmd.FailOnError(err, "Failed to load CT submission bundle")
		for _, cert := range pemBundle {
			bundle = append(bundle, ct.ASN1Cert{Data: cert.Raw})
		}
	}

	tlsConfig, err := c.Publisher.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	pubi := publisher.New(bundle, bundles, c.Publisher.UserAgent, logger, scope)

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, l, err := bgrpc.NewServer(c.Publisher.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup Publisher gRPC server")
	gw := bgrpc.NewPublisherServerWrapper(pubi)
	pubpb.RegisterPublisherServer(grpcSrv, gw)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)

	go cmd.CatchSignals(logger, func() {
		hs.Shutdown()
		grpcSrv.GracefulStop()
	})

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(l))
	cmd.FailOnError(err, "Publisher gRPC service failed")
}
