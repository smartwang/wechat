package biz

import (
	"github.com/smartwang/wechat/message"
	"io"
	"fmt"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"github.com/smartwang/wechat/message/types"
	"sort"
	"crypto/sha1"
	"strings"
	"time"
	"strconv"
)

type BizMessage struct {
	CorpID		string
	Token       string
	Timestamp   string
	Nonce       string
	SignatureIn string
	Key         string
	message.Message
}
func (m *BizMessage) PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (m *BizMessage) PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}


// Message Interface implement
func (m *BizMessage) Signature(data string) string {
	sl := []string{m.Token, m.Timestamp, m.Nonce, data}
	sort.Strings(sl)
	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))
	return fmt.Sprintf("%x", s.Sum(nil))
}

// https://golang.org/src/crypto/cipher/example_test.go
func (m *BizMessage) Encrypt(plantText, key string) (encryptText string, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key + "=")
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes) //选择加密算法
	if err != nil {
		return "", err
	}

	var length = make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(plantText)))
	s := [][]byte{
		length,
		[]byte(plantText),
	}
	padText := m.PKCS7Padding(bytes.Join(s, []byte("")), block.BlockSize())
	cipherText := make([]byte, aes.BlockSize + len(padText))

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	blockModel := cipher.NewCBCEncrypter(block, iv)
	blockModel.CryptBlocks(cipherText[aes.BlockSize:], padText)
	encryptText = base64.StdEncoding.EncodeToString(cipherText)
	return
}

func (m *BizMessage) Decrypt(encryptText, key string) (plantText string, err error) {
	cipherText, err := base64.StdEncoding.DecodeString(encryptText)
	if err != nil {
		return "", err
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key + "=")
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	if len(cipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	data := m.PKCS7UnPadding(cipherText)
	// 从dump下来的数据看，实际前4字节为长度，微信文档上说的似乎有误
	length := int32(binary.BigEndian.Uint32(data[0:4]))
	fmt.Println(hex.Dump(data))
	msg := data[4 : 4+length]
	return string(msg), nil
}

func (m *BizMessage) VerifyURL(echoStr string) (string, error) {
	signatureGen := m.Signature(echoStr)
	fmt.Println(signatureGen)
	if signatureGen != m.SignatureIn {
		return "", errors.New("签名错误")
	}
	decryptedEchoStr, err := m.Decrypt(echoStr, m.Key)
	if err != nil {
		return "", err
	}
	return decryptedEchoStr, nil
}

func (m *BizMessage) ParseRequest(data []byte) (interface{}, error) {
	result := &types.ReceivedData{}
	err := xml.Unmarshal(data, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (m *BizMessage) HandleClick(encryptText string) (types.WxClickMessage, error) {
	text, err := m.Decrypt(encryptText, m.Key)
	if err != nil {
		return types.WxClickMessage{}, err
	}
	result := types.WxClickMessage{}
	err = xml.Unmarshal([]byte(text), result)
	return result, err
}

func (m *BizMessage) HandleText(encryptText string) (types.WxTextMessage, error) {
	text, err := m.Decrypt(encryptText, m.Key)
	if err != nil {
		return types.WxTextMessage{}, err
	}
	result := types.WxTextMessage{}
	err = xml.Unmarshal([]byte(text), result)
	return result, err
}

func (m *BizMessage) PackageText(msg string) (string, error) {
	msgEncrypt, err := m.Encrypt(msg, m.Key)
	if err != nil {
		return "", err
	}
	msgSignature := m.Signature(msgEncrypt)
	timestamp := time.Now().Unix()
	nonce := timestamp % 100000

	response, err := xml.Marshal(types.ResponseData{
		Encrypt: types.CDATA{msgEncrypt},
		MsgSignature: types.CDATA{msgSignature},
		TimeStamp: timestamp,
		Nonce: types.CDATA{strconv.Itoa(int(nonce))},
	})
	if err != nil {
		return "", err
	}
	return string(response), nil
}

