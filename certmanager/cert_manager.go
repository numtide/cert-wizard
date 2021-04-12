package certmanager

import (
	"github.com/numtide/cert-wizard/appcontext"
)

type subscriptionRemoval struct {
	vaultPathAndDomain appcontext.VaultPathAndDomain
	subscription       int
}

type subscriptionAddition struct {
	vaultPathAndDomain appcontext.VaultPathAndDomain
	sub                chan appcontext.CertAndKey
	resp               chan int
}

type CertManager struct {
	knownCerts            map[appcontext.VaultPathAndDomain]appcontext.CertAndKey
	subscriptions         map[appcontext.VaultPathAndDomain]map[int](chan appcontext.CertAndKey)
	appContext            appcontext.AppContext
	subscriptionRemovals  chan subscriptionRemoval
	subscriptionAdditions chan subscriptionAddition
	lastSubscriptionID    int
	certUpdates           chan certUpdate
}

func New(appContext appcontext.AppContext) appcontext.CertManager {
	cm := &CertManager{
		appContext:            appContext,
		subscriptions:         make(map[appcontext.VaultPathAndDomain]map[int](chan appcontext.CertAndKey)),
		knownCerts:            make(map[appcontext.VaultPathAndDomain]appcontext.CertAndKey),
		subscriptionRemovals:  make(chan subscriptionRemoval),
		subscriptionAdditions: make(chan subscriptionAddition),
		certUpdates:           make(chan certUpdate),
	}

	go cm.run()

	return cm

}

func (c *CertManager) run() {
mainLoop:
	for {
		select {
		case r := <-c.subscriptionRemovals:
			subs, found := c.subscriptions[r.vaultPathAndDomain]
			if !found {
				// TODO something is fishy, log this!
				continue mainLoop
			}

			sub, found := subs[r.subscription]
			if !found {
				// TODO something is fishy, log this!
				continue mainLoop
			}

			close(sub)

			// TODO maybe check first and log if not found
			delete(subs, r.subscription)
			if len(subs) == 0 {
				// TODO - shut down cert goroutine
				delete(c.subscriptions, r.vaultPathAndDomain)
			}

		case s := <-c.subscriptionAdditions:
			subs, found := c.subscriptions[s.vaultPathAndDomain]
			if !found {
				subs = make(map[int]chan appcontext.CertAndKey)
				c.subscriptions[s.vaultPathAndDomain] = subs
				go runCertAgent(s.vaultPathAndDomain, c.certUpdates, c.appContext)
			}

			c.lastSubscriptionID++
			id := c.lastSubscriptionID
			subs[id] = s.sub

			s.resp <- id

			cert, certFound := c.knownCerts[s.vaultPathAndDomain]
			if certFound {
				s.sub <- cert
			}

		case cu := <-c.certUpdates:
			subs, found := c.subscriptions[cu.vaultPathAndDomain]
			if !found {
				c.appContext.Logger.Warn("received update without anyone subscribing")
				continue mainLoop
			}

			for _, v := range subs {
				// TODO? select in order not to block
				v <- cu.cert
			}

			c.knownCerts[cu.vaultPathAndDomain] = cu.cert
		}
	}
}

func (c *CertManager) SubscribeToCertificate(vaultPathAndDomain appcontext.VaultPathAndDomain) (chan appcontext.CertAndKey, func()) {
	c.appContext.Logger.With("vaultPathAndDomain", vaultPathAndDomain).Info("subscribed to certificate")
	ch := make(chan appcontext.CertAndKey)
	resp := make(chan int)
	c.subscriptionAdditions <- subscriptionAddition{vaultPathAndDomain: vaultPathAndDomain, sub: ch, resp: resp}
	subID := <-resp
	return ch, func() {
		c.subscriptionRemovals <- subscriptionRemoval{vaultPathAndDomain: vaultPathAndDomain, subscription: subID}
	}
}
