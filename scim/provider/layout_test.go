package provider

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

func randAlphaStr(length int) string {
	if length <= 0 {
		panic(error.Error)
	}
	rand.Seed(time.Now().UnixNano())
	// A-Z 65 - 90
	// a-z 97 - 122

	chars := make([]uint8, length)
	for i := 0; i < length; i++ {
		b := uint8(rand.Intn(122))

		if b < 65 {
			b = (65 + b)
		}

		if b > 122 {
			i--
			//fmt.Println("continuing", b)
			continue
		}

		if b > 90 && b < 97 {
			b += 6
		}

		fmt.Println(b)
		chars[i] = b
	}

	return string(chars)
}

var rootLoc = "/tmp/"

func TestLayoutCreation(t *testing.T) {
	name := randAlphaStr(5)
	fmt.Println(name)
	dir := rootLoc + name
	layout, _ := NewLayout(dir, true)

	if layout == nil {
		t.Errorf("Failed to create layout %s", dir)
	}

	assertDir(layout.ConfDir, t)
	assertDir(layout.DataDir, t)
	assertDir(layout.LogDir, t)
	assertDir(layout.SchemaDir, t)
	assertDir(layout.ResTypesDir, t)

	// remove the directory
	os.Remove(layout.SchemaDir)

	// and create a file with the same name
	os.Create(layout.SchemaDir)

	// layout creation must fail
	layout, err := NewLayout(dir, true)

	if err == nil {
		t.Errorf("Layout creation must fail due to failed schema directory creation %#v", layout)
	}

	os.RemoveAll(dir)
}

func assertDir(dirName string, t *testing.T) {
	finfo, err := os.Stat(dirName)

	if err != nil {
		t.Error(err)
	}

	if !finfo.IsDir() {
		t.Errorf("%s is not a directory", dirName)
	}
}
