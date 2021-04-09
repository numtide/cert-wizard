package main

import (
	"context"
	"fmt"
	"log"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
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
		},
		Action: func(c *cli.Context) error {
			config, err := clientcmd.BuildConfigFromFlags("", c.String("kubeconfig"))
			if err != nil {
				return errors.Wrap(err, "while creating k8s cluster config")
			}

			kubeclient, err := kubernetes.NewForConfig(config)
			if err != nil {
				return errors.Wrap(err, "while creating k8s client")
			}

			ingresses := kubeclient.NetworkingV1().Ingresses(corev1.NamespaceAll)

			w, err := ingresses.Watch(context.Background(), v1.ListOptions{})

			if err != nil {
				return errors.Wrap(err, "while creating event watch")
			}

			defer w.Stop()

			for ev := range w.ResultChan() {
				obj := ev.Object.(*networkingv1.Ingress)
				switch ev.Type {
				case watch.Added:
					log.Println("ADDED", fmt.Sprintf("%s:%s", obj.ObjectMeta.Namespace, obj.ObjectMeta.Name))
				case watch.Deleted:
					log.Println("DELETED", fmt.Sprintf("%s:%s", obj.ObjectMeta.Namespace, obj.ObjectMeta.Name))
				case watch.Modified:
					log.Println("MODIFIED", fmt.Sprintf("%s:%s", obj.ObjectMeta.Namespace, obj.ObjectMeta.Name))
				}
			}

			return nil

		},
	}
	app.RunAndExitOnError()

}
