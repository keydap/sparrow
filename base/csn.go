// Copyright 2017 Keydap. All rights reserved.
// Use of this source code is governed by a Apache
// license that can be found in the LICENSE file.

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
