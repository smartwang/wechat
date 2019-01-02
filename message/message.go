package message

import "github.com/smartwang/wechat/message/types"

type Message interface {
	Signature(timestamp, nonce, data string) string
	Encrypt(plantText, key string) (encryptText string, err error)
	Decrypt(encryptText, key string) (plantText string, err error)
	VerifyURL(timestamp, nonce, echoStr string) (string, error)

	ParseRequest(data []byte) (interface{}, error)	// 解析请求body
	HandleClick(encryptText string) (types.WxClickMessage, error)
	HandleText(encryptText string) (types.WxTextMessage, error)

	PackageText(msg, toUser string) (string, error)	// 用于构造文本消息
	// TODO: 实现其他如获取用户名、消息类型等信息的方法
}

