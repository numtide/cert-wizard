package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/numtide/cert-wizard/appcontext"
	"github.com/numtide/cert-wizard/certmanager"
	"github.com/numtide/cert-wizard/event"
	"github.com/numtide/cert-wizard/k8sdispatcher"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "kubeconfig",
				EnvVars: []string{"KUBECONFIG"},
			},
			&cli.StringFlag{
				Name:    "vaultaddr",
				EnvVars: []string{"VAULT_ADDR"},
			},
			&cli.StringFlag{
				Name:    "vault-username",
				EnvVars: []string{"VAULT_USERNAME"},
			},
			&cli.StringFlag{
				Name:    "vault-password",
				EnvVars: []string{"VAULT_PASSWORD"},
			},
			&cli.StringFlag{
				Name:    "vault-path",
				EnvVars: []string{"VAULT_PATH"},
			},
		},
		Action: func(c *cli.Context) error {
			lc := zap.NewProductionConfig()
			lc.EncoderConfig.TimeKey = "timestamp"
			lc.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
			lc.OutputPaths = []string{"stdout"}

			z, err := lc.Build()
			if err != nil {
				return errors.Wrap(err, "while creating logger")
			}

			logger := z.Sugar()

			vc, err := api.NewClient(api.DefaultConfig())
			if err != nil {
				return errors.Wrap(err, "while creating vault client")
			}

			// to pass the password
			options := map[string]interface{}{
				"password": c.String("vault-password"),
			}
			path := fmt.Sprintf("auth/userpass/login/%s", c.String("vault-username"))

			// PUT call to get a token
			secret, err := vc.Logical().Write(path, options)
			if err != nil {
				return errors.Wrap(err, "while logging in to vault")
			}

			token := secret.Auth.ClientToken
			vc.SetToken(token)

			appContext := appcontext.AppContext{
				VaultClient: vc,
				Logger:      logger,
				CertPath:    c.String("vault-path"),
			}

			cm := certmanager.New(appContext)
			appContext.CertManager = cm

			config, err := clientcmd.BuildConfigFromFlags("", c.String("kubeconfig"))
			if err != nil {
				return errors.Wrap(err, "while creating k8s cluster config")
			}

			kubeclient, err := kubernetes.NewForConfig(config)
			if err != nil {
				return errors.Wrap(err, "while creating k8s client")
			}

			appContext.KubeClient = kubeclient

			ingresses := kubeclient.NetworkingV1().Ingresses(corev1.NamespaceAll)

			w, err := ingresses.Watch(context.Background(), v1.ListOptions{})

			if err != nil {
				return errors.Wrap(err, "while creating event watch")
			}

			defer w.Stop()

			eventChannel := make(chan event.Event)

			go k8sdispatcher.Dispatch(eventChannel, appContext)

			for ev := range w.ResultChan() {
				obj := ev.Object.(*networkingv1.Ingress)

				switch ev.Type {
				case watch.Added:
					eventChannel <- event.Event{
						Type: event.Create,
						Data: obj,
					}
				case watch.Deleted:
					eventChannel <- event.Event{
						Type: event.Delete,
						Data: obj,
					}
				case watch.Modified:
					eventChannel <- event.Event{
						Type: event.Update,
						Data: obj,
					}
				}

			}

			return nil

		},
	}
	app.RunAndExitOnError()

}
