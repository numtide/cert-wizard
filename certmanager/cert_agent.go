package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/numtide/cert-wizard/appcontext"
	"github.com/pkg/errors"
)

type certUpdate struct {
	vaultPathAndDomain appcontext.VaultPathAndDomain
	cert               appcontext.CertAndKey
}

func runCertAgent(vaultPathAndDomain appcontext.VaultPathAndDomain, updates chan certUpdate, appContext appcontext.AppContext) {

	logger := appContext.Logger.With("pathAndDomain", vaultPathAndDomain)

	logger.Info("cert agent started")

	noCertBackoff := backoff.NewExponentialBackOff()
	noCertBackoff.InitialInterval = 1 * time.Second
	noCertBackoff.MaxInterval = 60 * time.Second

	var cert *tls.Certificate
	var raw *appcontext.CertAndKey

	for {

		var sleepDuration time.Duration
		var err error

		raw, cert, err = getCertFromVault(vaultPathAndDomain, appContext)
		if err != nil {
			logger.With("error", err).Error("while getting cert")
			sleepDuration = noCertBackoff.NextBackOff()
		} else {
			updates <- certUpdate{vaultPathAndDomain: vaultPathAndDomain, cert: *raw}
			noCertBackoff.Reset()
		}

		if cert != nil {
			expiresAt := cert.Leaf.NotAfter

			validFor := expiresAt.Sub(time.Now())

			if validFor < time.Hour {
				cert = nil
				continue
			}

			if validFor < 24*time.Hour {
				sleepDuration = 5 * time.Minute
			}

			if validFor <= 7*24*time.Hour {
				sleepDuration = time.Hour
			}

			sleepDuration = validFor - (7 * 24 * time.Hour)

		}

		appContext.Logger.With("vaultPathAndDomain", vaultPathAndDomain, "sleepDuration", sleepDuration).Info("sleeping")

		time.Sleep(sleepDuration)

	}

}

func getCertFromVault(vaultPathAndDomain appcontext.VaultPathAndDomain, appContext appcontext.AppContext) (*appcontext.CertAndKey, *tls.Certificate, error) {
	res, err := appContext.VaultClient.Logical().Write(vaultPathAndDomain.VaultPath, map[string]interface{}{
		"common_name": vaultPathAndDomain.Domain,
	})

	if err != nil {
		return nil, nil, errors.Wrap(err, "while getting certificate")
	}

	// res.Data
	// cert
	// domain
	// issuer_cert
	// private_key

	certPEM := res.Data["cert"].(string)
	privateKeyPEM := res.Data["private_key"].(string)

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(privateKeyPEM))
	if err != nil {
		return nil, nil, errors.Wrap(err, "while parsing certificate")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, errors.Wrap(err, "while parsing leaf cert")
	}

	cert.Leaf = leaf

	return &appcontext.CertAndKey{Cert: certPEM, Key: privateKeyPEM}, &cert, nil

}
