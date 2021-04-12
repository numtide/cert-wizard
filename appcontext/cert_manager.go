package appcontext

type CertAndKey struct {
	Cert string
	Key  string
}

type VaultPathAndDomain struct {
	VaultPath string
	Domain    string
}

type CertManager interface {
	SubscribeToCertificate(pathAndDomain VaultPathAndDomain) (chan CertAndKey, func())
}
