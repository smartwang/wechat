package message


type Message interface {
	Signature(data string) string
	Encrypt(plantText, key string) (encryptText string, err error)
	Decrypt(encryptText, key string) (plantText string, err error)
	VerifyURL(echoStr string) (string, error)
	Package(msg string) (string, error)
	Read() (string, error)
	// TODO: 实现其他如获取用户名、消息类型等信息的方法
}

