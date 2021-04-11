package k8sdispatcher

import (
	"fmt"

	"github.com/numtide/cert-wizard/appcontext"
	"github.com/numtide/cert-wizard/event"
	"github.com/numtide/cert-wizard/ingressagent"
)

func Dispatch(ch chan event.Event, appCtx appcontext.AppContext) {

	agents := map[string]chan event.Event{}

	shutdownChan := make(chan string)

	defer func() {
		for _, a := range agents {
			close(a)
		}
	}()

eventLoop:
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			key := fmt.Sprintf("%s:%s", ev.Data.ObjectMeta.Namespace, ev.Data.ObjectMeta.Name)
			ag, found := agents[key]
			switch ev.Type {
			case event.Create, event.Update:
				if !found {
					ag = make(chan event.Event)
					go ingressagent.Process(ag, appCtx, func() { shutdownChan <- key })
					agents[key] = ag
				}
			case event.Delete:
				if !found {
					continue eventLoop
				}
				close(ag)
				continue eventLoop
			}
			appCtx.Logger.With("key", key, "type", ev.Type).Info("sending event")
			ag <- ev
		case key := <-shutdownChan:
			ag, found := agents[key]
			if found {
				close(ag)
			}
			delete(agents, key)
			appCtx.Logger.With("key", key).Info("ingress agent terminated")
		}
	}
}
