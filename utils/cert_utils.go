// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.
package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"math/rand"
	"os"
	"time"
)

// Generates a self-signed certificate and stores the PEM encoded certificate and private key
// with the names {suffix}.cer and {suffix}.key under the given directory.
func CreateCert(dirName string, suffix string) error {

	template := &x509.Certificate{}
	template.EmailAddresses = []string{"support@keydap.com"}
	name := pkix.Name{}
	name.CommonName = "Sparrow Server"
	name.Country = []string{"IN"}
	name.Locality = []string{"TS"}
	name.Organization = []string{"Keydap"}
	name.OrganizationalUnit = []string{"IdM"}

	template.Issuer = name
	template.Subject = name

	template.NotAfter = time.Now().AddDate(10, 0, 0)
	template.NotBefore = time.Now()

	template.SignatureAlgorithm = x509.SHA256WithRSA

	now := time.Now().Unix()
	random := rand.New(rand.NewSource(now))
	template.SerialNumber = big.NewInt(now)

	priv, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		return err
	}

	pub := priv.Public()

	cer, err := x509.CreateCertificate(random, template, template, pub, priv)

	if err != nil {
		return err
	}

	err = os.Mkdir(dirName, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	cerFile, err := os.Create(dirName + string(os.PathSeparator) + suffix + ".cer")
	if err != nil {
		return err
	}

	block := &pem.Block{}
	block.Bytes = cer
	block.Type = "CERTIFICATE"
	err = pem.Encode(cerFile, block)
	cerFile.Close()
	if err != nil {
		return err
	}

	keyFile, err := os.Create(dirName + string(os.PathSeparator) + suffix + ".key")
	if err != nil {
		return err
	}

	block.Bytes = x509.MarshalPKCS1PrivateKey(priv)
	block.Type = "RSA PRIVATE KEY"
	err = pem.Encode(keyFile, block)
	keyFile.Close()
	if err != nil {
		return err
	}

	return nil
}
