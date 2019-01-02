package biz

import (
	"testing"
)

var testMsg = &BizMessage{
	Token: "abcdefg",
	Timestamp: "1546408477",
	Nonce: "1232",
	SignatureIn: "7960dd476c4b4348c3529ecf9e6431b8eaf37cc7",
	Key: "DF7TcyiKUDn81EejpSh3v3l4CmO7zvGaGkSYqmzTBz9",
}

var msgText = "hello world"

func TestSignature(t *testing.T) {
	t.Log(testMsg.Signature(msgText))
}

func TestEncrypt(t *testing.T){
	result, err := testMsg.Encrypt(msgText, testMsg.Key)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(result)
	plainText, err := testMsg.Decrypt(result, testMsg.Key)
	t.Log(plainText)
}

func TestPackage(t *testing.T)  {
	result, err := testMsg.Package(msgText)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(result)
}

func TestVerifyUrl(t *testing.T) {
	result, err := testMsg.VerifyURL("+Y5/ItU5iOFPn6OYzxVt8/wCjRUvWC1ZsIZtsG1e9sM=")
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(result)
	if result != msgText {
		t.Error("url验证失败")
	}
}