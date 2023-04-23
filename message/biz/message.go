package biz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/smartwang/wechat/message"
	"github.com/smartwang/wechat/message/types"
)

type BizMessage struct {
	CorpID      string
	SignatureIn string
	Token       string
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
func (m *BizMessage) Signature(timestamp, nonce, data string) string {
	sl := []string{m.Token, timestamp, nonce, data}
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
	cipherText := make([]byte, aes.BlockSize+len(padText))

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
	//fmt.Println(hex.Dump(data))
	msg := data[4 : 4+length]
	return string(msg), nil
}

func (m *BizMessage) VerifyURL(timestamp, nonce, echoStr string) (string, error) {
	signatureGen := m.Signature(timestamp, nonce, echoStr)
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
	result := &types.WxClickMessage{}
	err = xml.Unmarshal([]byte(text), result)
	return *result, err
}

func (m *BizMessage) HandleText(encryptText string) (types.WxTextMessage, error) {
	text, err := m.Decrypt(encryptText, m.Key)
	if err != nil {
		return types.WxTextMessage{}, err
	}
	result := &types.WxTextMessage{}
	err = xml.Unmarshal([]byte(text), result)
	return *result, err
}

func (m *BizMessage) PackageText(msg, toUser string) (string, error) {
	textMsg, err := xml.Marshal(types.WxTextMessage{
		FromUserName: types.CDATA{m.CorpID},
		ToUserName:   types.CDATA{toUser},
		CreateTime:   time.Now().Unix(),
		MsgType:      types.CDATA{"text"},
		Content:      types.CDATA{msg},
	})
	msgEncrypt, err := m.Encrypt(string(textMsg), m.Key)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Unix()
	nonce := timestamp % 100000
	msgSignature := m.Signature(strconv.Itoa(int(timestamp)), strconv.Itoa(int(nonce)), msgEncrypt)
	response, err := xml.Marshal(types.ResponseData{
		Encrypt:      types.CDATA{msgEncrypt},
		MsgSignature: types.CDATA{msgSignature},
		TimeStamp:    timestamp,
		Nonce:        types.CDATA{strconv.Itoa(int(nonce))},
	})
	if err != nil {
		return "", err
	}
	return string(response), nil
}
