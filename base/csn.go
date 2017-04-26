package base

import ()

// Interface representing a CSN
type Csn interface {
	TimeMillis() int64

	ChangeCount() uint32

	ReplicaId() uint16

	ModificationCount() uint32

	String() string
}
