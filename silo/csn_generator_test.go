package silo

import (
	"testing"
)

func TestCsnGeneration(t *testing.T) {
	var replicaId uint16 = 0

	cg := NewCsnGenerator(replicaId)
	for i := 0; i < 1000; i++ {
		csn1 := cg.NewCsn()
		csn2 := cg.NewCsn()
		//fmt.Println(csn1, " == ", csn2)
		if csn1.String() == csn2.String() {
			t.Errorf("CSNs generated at anytime in the same process should never be equal %s %s", csn1, csn2)
		}
	}
}
