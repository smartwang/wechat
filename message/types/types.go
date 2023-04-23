package types

import (
	"encoding/xml"
)

type CDATA struct {
	Text string `xml:",cdata"`
}

type ReceivedData struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName CDATA
	Encrypt    CDATA
	AgentID    CDATA
}

type ResponseData struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      CDATA
	MsgSignature CDATA
	TimeStamp    int64
	Nonce        CDATA
}

// 菜单事件
type WxClickMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   CDATA
	FromUserName CDATA
	CreateTime   int64
	MsgType      CDATA
	Event        CDATA
	EventKey     CDATA
	AgentID      int
}

type WxTextMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   CDATA
	FromUserName CDATA
	CreateTime   int64
	MsgType      CDATA
	Content      CDATA
}
