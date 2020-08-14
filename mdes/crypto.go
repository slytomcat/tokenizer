package mdes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	oauth "github.com/mastercard/oauth1-signer-go"
	"github.com/mastercard/oauth1-signer-go/utils"
	tools "github.com/slytomcat/tokenizer/tools"
)

// getRandom returns the specified number of random bytes or error
func getRandom(nBytes int) ([]byte, error) {
	buf := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("random bytes receiving error: %w", err)
	}
	return buf, nil
}

// unpaddingPKCS7 removes padding
func unpaddingPKCS7(text []byte) []byte {
	lentgth := len(text)
	padding := int(text[lentgth-1])
	return text[:lentgth-padding]
}

// paddingPKCS7 makes padding
func paddingPKCS7(text []byte, blockSize int) []byte {
	padding := (blockSize - len(text)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padtext...)
}

// decryptAESCBC decypts ciphertext via AES-CBC
func decryptAESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	// make new AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation error: %w", err)
	}
	// make CBC mode decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// decryp data
	opentext := make([]byte, len(ciphertext))
	mode.CryptBlocks(opentext, ciphertext)

	return unpaddingPKCS7(opentext), nil
}

// encryptAESCBC encrypts opentext via AES-CBC
func encryptAESCBC(key, opentext []byte) ([]byte, []byte, error) {
	// make new AES chiper
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("AES cipher creation error: %w", err)
	}
	blockSize := block.BlockSize()

	// make the iv as secure random
	iv, err := getRandom(blockSize)
	if err != nil {
		return nil, nil, fmt.Errorf("iv creation error: %w", err)
	}

	// add padding
	opentext = paddingPKCS7(opentext, blockSize)

	// make CBC mode encryptor
	mode := cipher.NewCBCEncrypter(block, iv)

	// encrypt the payload
	ciphertext := make([]byte, len(opentext))
	mode.CryptBlocks(ciphertext, opentext)

	return iv, ciphertext, nil
}

func (m MDESapi) signer() *oauth.Signer {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.oAuthSigner
}

func (m MDESapi) decrypKey() *rsa.PrivateKey {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.storedDecryptKey
}

func (m MDESapi) encryptKey() (*rsa.PublicKey, string) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.storedEncryptKey, m.storedEncryptKeyFP
}

func (m *MDESapi) initKeys(conf *MDESconf) error {

	// load signing key
	// TO DO get password from secure storage
	signingKey, err := utils.LoadSigningKey(conf.SignKey, "keyst0repassw0rd")
	if err != nil {
		return err
	}

	m.oAuthSigner = &oauth.Signer{ConsumerKey: conf.APIKey, SigningKey: signingKey}

	// TO DO get password from secure storage
	m.storedDecryptKey, err = utils.LoadSigningKey(conf.DecryptKey, "keystorepassword")
	if err != nil {
		return err
	}

	// load encryption public key
	encryptKeyData, err := tools.ReadFile(conf.EcryptKey)
	if err != nil {
		return err
	}
	data, _ := pem.Decode(encryptKeyData)
	cert, err := x509.ParseCertificate(data.Bytes)
	if err != nil {
		return err
	}
	ok := false
	m.storedEncryptKey, ok = cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("can't convert public key from certificate")
	}
	// TO DO: load fingerprint from key storage
	m.storedEncryptKeyFP = conf.EncrypKeyFp
	return nil
}
