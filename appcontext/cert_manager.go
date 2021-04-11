package appcontext

type CertAndKey struct {
	Cert string
	Key  string
}

type CertManager interface {
	SubscribeToCertificate(domain string) (chan CertAndKey, func())
}
