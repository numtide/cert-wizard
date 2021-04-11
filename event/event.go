package event

import networkingv1 "k8s.io/api/networking/v1"

type EventType int

const (
	Create EventType = iota
	Update
	Delete
)

type Event struct {
	Type EventType
	Data *networkingv1.Ingress
}
