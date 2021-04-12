package ingressagent

import (
	"context"

	"github.com/numtide/cert-wizard/appcontext"
	"github.com/numtide/cert-wizard/event"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Process(input chan event.Event, appCtx appcontext.AppContext, terminate func()) {

	defer terminate()

	initial := <-input

	var certSubscription chan (appcontext.CertAndKey)
	var certSubscriptionCancel func()

	namespace := initial.Data.Namespace
	var secretName string

	vaultPath := initial.Data.ObjectMeta.Annotations["cert-wizard.numtide.com/vault-path"]

	if vaultPath != "" && len(initial.Data.Spec.TLS) > 0 {
		first := initial.Data.Spec.TLS[0]
		if len(first.Hosts) > 0 {
			domain := first.Hosts[0]
			secretName = first.SecretName
			certSubscription, certSubscriptionCancel = appCtx.CertManager.SubscribeToCertificate(appcontext.VaultPathAndDomain{Domain: domain, VaultPath: vaultPath})
		}
	}

	defer func() {
		if certSubscriptionCancel != nil {
			certSubscriptionCancel()
		}
	}()

	for {

		select {
		case _, ok := <-input:
			// just ignore ir for now
			if !ok {
				return
			}

		case cert := <-certSubscription:
			err := setSecret(namespace, secretName, cert, appCtx)
			if err != nil {
				appCtx.Logger.With("namespace", namespace, "name", secretName, "error", err).Error("while creating ingress secret")
			}
		}

	}

}

func setSecret(namespace, secretName string, cert appcontext.CertAndKey, appCtx appcontext.AppContext) error {
	secc := appCtx.KubeClient.CoreV1().Secrets(namespace)

	_, err := secc.Get(context.Background(), secretName, v1.GetOptions{})
	// TODO: take into account existing secret - do not update unless annotation is reckognized!
	if !kerrors.IsNotFound(err) {
		if err != nil {
			return errors.Wrap(err, "while checking existence of secret")
		}
		return errors.New("secret already exists")
	}

	_, err = secc.Create(context.Background(), &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name: secretName,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte(cert.Cert),
			"tls.key": []byte(cert.Key),
		},
	}, v1.CreateOptions{})

	if err != nil {
		return errors.Wrap(err, "while creating secret")
	}

	return nil
}
