// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package base

import (
	"testing"
)

func TestCsnGeneration(t *testing.T) {
	var replicaId uint16 = 0

	cg := NewCsnGenerator(replicaId)

	for i := 0; i < 1000; i++ {
		csn1 := cg.NewCsn().String()
		csn2 := cg.NewCsn().String()

		l := len(csn1)
		if l != 40 {
			t.Errorf("Invalid CSN length %d %s", l, csn1)
		}

		//fmt.Println(csn1, " == ", csn2)
		if csn1 == csn2 {
			t.Errorf("CSNs generated at anytime in the same process should never be equal %s %s", csn1, csn2)
		}
	}
}
