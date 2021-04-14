package ingressagent

import (
	"context"

	"github.com/numtide/cert-wizard/appcontext"
	"github.com/numtide/cert-wizard/event"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ingressState struct {
	namespace string
	appCtx    appcontext.AppContext

	certSubscription       chan appcontext.CertAndKey
	certSubscriptionCancel func()

	vaultPath  string
	domain     string
	secretName string

	cert appcontext.CertAndKey

	logger *zap.SugaredLogger
}

func newIngressState(namespace, name string, appCtx appcontext.AppContext) *ingressState {
	return &ingressState{
		namespace: namespace,
		appCtx:    appCtx,
		logger:    appCtx.Logger.With("process", "ingress_agent", "namespace", namespace, "name", name),
	}
}

func (c *ingressState) updateIngress(ing *networkingv1.Ingress) {
	vaultPath := ing.ObjectMeta.Annotations["cert-wizard.numtide.com/vault-path"]
	var secretName string
	var domain string
	if len(ing.Spec.TLS) > 0 {
		tls := ing.Spec.TLS[0]
		secretName = tls.SecretName
		if len(tls.Hosts) > 0 {
			domain = tls.Hosts[0]
		}
	}
	if c.vaultPath != vaultPath || c.domain != domain {
		if c.certSubscription != nil {
			c.certSubscriptionCancel()
			c.certSubscription = nil
			c.certSubscriptionCancel = nil
		}
		c.vaultPath = vaultPath
		c.domain = domain
		if c.vaultPath != "" && c.domain != "" {
			c.certSubscription, c.certSubscriptionCancel = c.appCtx.CertManager.SubscribeToCertificate(appcontext.VaultPathAndDomain{VaultPath: vaultPath, Domain: domain})
		}
	}

	if secretName != c.secretName {
		c.storeSecret(secretName)
	}

}

func (c *ingressState) storeSecret(newSecretName string) {
	secc := c.appCtx.KubeClient.CoreV1().Secrets(c.namespace)

	if c.secretName != "" {
		err := secc.Delete(context.Background(), c.secretName, v1.DeleteOptions{})
		if kerrors.IsNotFound(err) {
			// all good, go ahead and create the new one
		} else if err != nil {
			c.logger.With("error", err, "secretName", c.secretName).Error("while deleting secret")
		}

	}

	if newSecretName != c.secretName {
		err := secc.Delete(context.Background(), newSecretName, v1.DeleteOptions{})
		if kerrors.IsNotFound(err) {
			// all good, go ahead and create the new one
		} else if err != nil {
			c.logger.With("error", err, "secretName", newSecretName).Error("while deleting secret")
			return
		}
	}

	c.secretName = newSecretName

	if newSecretName == "" {
		c.logger.Warn("no secret stored because secret name is empty")
		return
	}

	_, err := secc.Create(context.Background(),
		&corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name: newSecretName,
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": []byte(c.cert.Cert),
				"tls.key": []byte(c.cert.Key),
			},
		},
		v1.CreateOptions{},
	)

	if err != nil {
		c.logger.With("error", err, "secretName", newSecretName).Error("while creating secret")
	} else {
		c.logger.With("secretName", newSecretName).Info("TLS secret stored")
	}

}

func (c *ingressState) updateCert(cert appcontext.CertAndKey) {
	c.cert = cert
	c.storeSecret(c.secretName)
}

func (c *ingressState) cleanup() {
	if c.certSubscription != nil {
		c.certSubscriptionCancel()
		c.certSubscription = nil
		c.certSubscriptionCancel = nil
	}
	secc := c.appCtx.KubeClient.CoreV1().Secrets(c.namespace)

	if c.secretName == "" {
		return
	}

	err := secc.Delete(context.Background(), c.secretName, v1.DeleteOptions{})
	if kerrors.IsNotFound(err) {
		// all good, go ahead and create the new one
	} else if err != nil {
		c.logger.With("error", err, "secretName", c.secretName).Error("while deleting secret")
	}

}

func Process(input chan event.Event, appCtx appcontext.AppContext, terminate func()) {

	defer terminate()

	initial := <-input

	state := newIngressState(initial.Data.ObjectMeta.Namespace, initial.Data.ObjectMeta.Name, appCtx)

	state.updateIngress(initial.Data)

	defer state.cleanup()

	for {

		select {
		case ev, ok := <-input:
			if !ok {
				return
			}
			state.updateIngress(ev.Data)

		case cert := <-state.certSubscription:
			state.updateCert(cert)
		}

	}

}
