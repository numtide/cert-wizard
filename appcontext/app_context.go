package appcontext

import (
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type AppContext struct {
	KubeClient  *kubernetes.Clientset
	VaultClient *api.Client
	Logger      *zap.SugaredLogger
	CertManager CertManager
}
