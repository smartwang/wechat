package biz

import (
	"testing"
)

var testMsg = &BizMessage{
	CorpID: "wxtestaffbfc22fake",
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

func TestParse(t *testing.T)  {
	testData := `<xml><ToUserName><![CDATA[wx2afdaffbfc560963]]></ToUserName><Encrypt><![CDATA[L13U7TnuugL4vCwxwUJVeT++f+uG5f4nN1gQRhC8s1QFADUePgTWDrDvAsTQtQz/CFybrw9l/FIBmF2vZfNhjU/dLjxOdHNatSjm+sGpneXJGqGDXw54bjGLNIFET++CD4rjWrMMt3t7uGNxkXwf9vA27qD0TtUgtwjP7VWCU+7TCSx/dtIWwiMyjh2rNzuUwzNK6Vz82MwAAJeUvF2Lz1zkVdPu8Tqy1TTryYhq2+7kQg9iFnqk9g/O2YCiM8oCOA/MnJha7Z69hKJQPkSrJe0jk75784AwQ08zDYaWKUlDCbGvjn93WCzuA7moL1bEs0GxwaWfRebbptwYN13TuRxbemacYqJcadY3MQkwuWAySGpdvEQMWzM0F2BjcNT4fbBvyt8yhpFQSiHG7Z7Yus7WJ42eqQ+vQiniEeADgjI=]]></Encrypt><AgentID><![CDATA[3]]></AgentID></xml>`

	result, err := testMsg.Parse([]byte(testData))
	if err != nil {
		t.Error(err.Error())
	}
	result, ok:= result.(*ReceivedData)
	if !ok {
		t.Error("格式错误")
	}
	t.Log(result)
}