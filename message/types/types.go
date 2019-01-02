package types

import "encoding/xml"

type CDATA struct {
	Text string `xml:",cdata"`
}

type WxClickMessage struct {
	XMLName      xml.Name `xml:"xml"`
	FromUserName CDATA
}

type WxTextMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName CDATA
	FromUserName CDATA
	CreateTime int64
	MsgType CDATA
	Content CDATA
}