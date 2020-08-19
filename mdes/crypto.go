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

// unpaddingPKCS7 checks and removes padding
func unpaddingPKCS7(text []byte) ([]byte, error) {
	length := len(text)
	padding := int(text[length-1])
	// try to perform check in more-less the same time for errors in different positions to avoid time based atacks
	var err error
	for _, b := range text[length-padding:] {
		if int(b) != padding {
			err = errors.New("wrong padding")
		}
	}
	if err != nil {
		return nil, err
	}
	return text[:length-padding], nil
}

// paddingPKCS7 makes padding
func paddingPKCS7(text []byte, blockSize int) []byte {
	padding := (blockSize - len(text)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padtext...)
}

// decryptAESCBC decypts cipherText via AES-CBC
func decryptAESCBC(key, iv, cipherText []byte) ([]byte, error) {
	// make new AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation error: %w", err)
	}
	// make CBC mode decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// decryp data
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)

	return unpaddingPKCS7(plainText)
}

// encryptAESCBC encrypts plainText via AES-CBC
func encryptAESCBC(key, plainText []byte) ([]byte, []byte, error) {
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
	plainText = paddingPKCS7(plainText, blockSize)

	// make CBC mode encryptor
	mode := cipher.NewCBCEncrypter(block, iv)

	// encrypt the payload
	cipherText := make([]byte, len(plainText))
	mode.CryptBlocks(cipherText, plainText)

	return iv, cipherText, nil
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
