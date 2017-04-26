// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
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
