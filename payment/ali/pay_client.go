package ali

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agui-coder/simple-admin-pay-common/payment/model"
	"github.com/go-pay/gopay"
	"github.com/go-pay/gopay/alipay"
	"github.com/suyuan32/simple-admin-common/utils/pointy"
	"github.com/zeromicro/go-zero/core/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"net/http"
)

// ClientConfig 没支付宝商户号就没写
// ClientConfig 实现了 pay.ClientConfig 接口
type ClientConfig struct {
	AppId                   string
	SignType                string
	PrivateKey              string
	AppPublicContent        string
	AlipayPublicContentRSA2 string
	AlipayRootContent       string
}

func (p ClientConfig) Validate() error {
	return nil
}

// Client 结构体实现了 PayClient 接口
type Client struct {
	ChannelId uint64
	Config    *ClientConfig
	client    *alipay.Client
}

func (a *Client) Init() error {
	// 初始化支付宝客户端
	// appid：应用ID
	// privateKey：应用私钥，支持PKCS1和PKCS8
	// isProd：是否是正式环境，沙箱环境请选择新版沙箱应用。
	client, err := alipay.NewClient(a.Config.AppId, a.Config.PrivateKey, false)
	if err != nil {
		logx.Error(err)
		return errors.New("支付客户端初始化异常")
	}

	// 自定义配置http请求接收返回结果body大小，默认 10MB
	//client.SetBodySize() // 没有特殊需求，可忽略此配置

	// 打开Debug开关，输出日志，默认关闭
	client.DebugSwitch = gopay.DebugOn

	// 设置支付宝请求 公共参数
	//    注意：具体设置哪些参数，根据不同的方法而不同，此处列举出所有设置参数
	client.SetCharset(alipay.UTF8). // 设置字符编码，不设置默认 utf-8
					SetSignType(a.Config.SignType).      // 设置签名类型，不设置默认 RSA2
					SetLocation(alipay.LocationShanghai) // 设置时区，不设置或出错均为默认服务器时间
	//SetReturnUrl("https://www.fmm.ink"). // 设置返回URL
	//SetNotifyUrl("https://www.fmm.ink"). // 设置异步通知URL
	//SetAppAuthToken() // TODO 设置第三方应用授权

	// 设置biz_content加密KEY，设置此参数默认开启加密
	// client.SetAESKey("1234567890123456")
	// 自动同步验签（只支持证书模式）
	// 传入 alipayPublicCert.crt 内容
	client.AutoVerifySign([]byte(a.Config.AlipayPublicContentRSA2))
	// 证书内容
	err = client.SetCertSnByContent([]byte(a.Config.AppPublicContent), []byte(a.Config.AlipayRootContent), []byte(a.Config.AlipayPublicContentRSA2))
	if err != nil {
		logx.Error(err)
		return err
	}
	a.client = client
	return nil
}

func (a Client) ParseOrderNotify(r *http.Request) (*model.OrderResp, error) {
	notifyReq, err := alipay.ParseNotifyToBodyMap(r)
	if err != nil {
		return nil, err
	}
	// 支付宝异步通知验签（公钥证书模式）
	_, err = alipay.VerifySignWithCert([]byte(a.Config.AlipayPublicContentRSA2), notifyReq)
	if err != nil {
		return nil, err
	}
	status := parseStatus(notifyReq.Get("trade_status"))
	if notifyReq.Get("refund_fee") != "" {
		status = pointy.GetPointer(model.REFUND)
	}
	if status == nil {
		return nil, errorx.NewApiInternalError(fmt.Sprintf("notifyReq:%s  的支付宝异步通知状态异常", notifyReq))
	}
	return model.Of(*status, notifyReq.Get("trade_no"), pointy.GetPointer(notifyReq.Get("seller_id")),
		model.ParseDate(notifyReq.Get("gmt_payment")), notifyReq.Get("out_trade_no"), notifyReq), nil
}

func (a Client) UnifiedOrder(context.Context, model.OrderUnifiedReq) (*model.OrderResp, error) {
	return nil, errorx.NewInvalidArgumentError("该客户端不能下单哦")
}

func (a Client) GetId() uint64 {
	return a.ChannelId
}

func (a Client) GetOrder(ctx context.Context, outTradeNo string) (*model.OrderResp, error) {
	bm := make(gopay.BodyMap)
	bm.Set("out_trade_no", outTradeNo)
	resp, err := a.client.TradeQuery(ctx, bm)
	if err != nil {
		return nil, err
	}
	if resp.Response.SubCode != "" { // 不成功，例如说订单不存在
		return &model.OrderResp{
			Status:           model.CLOSED,
			ChannelErrorCode: &resp.Response.SubCode,
			ChannelErrorMsg:  &resp.Response.SubMsg,
			OutTradeNo:       outTradeNo,
			RawData:          resp.Response,
		}, nil
	}
	status := parseStatus(resp.Response.TradeStatus)
	if status != nil {
		return nil, errorx.NewInvalidArgumentError(fmt.Sprintf("body(%v) 的 trade_status 不正确", resp.Response))
	}
	return &model.OrderResp{
		Status:         *status,
		ChannelOrderNo: resp.Response.TradeNo,
		ChannelUserId:  &resp.Response.BuyerUserId,
		SuccessTime:    model.ParseDate(resp.Response.SendPayDate),
		OutTradeNo:     outTradeNo,
		RawData:        resp.Response,
	}, nil
}

func (a *Client) Refresh(config model.ClientConfig) error {
	if *a.Config == config {
		return nil
	}
	logx.Infof("[refresh][客户端 %d 发生变化，重新初始化]", a.ChannelId)
	if clientConfig, ok := config.(ClientConfig); ok {
		a.Config = &clientConfig
	} else {
		return errorx.NewInvalidArgumentError(fmt.Sprintf("客户端%d重新初始化失败", a.ChannelId))
	}
	return nil
}

func (a Client) UnifiedRefund(ctx context.Context, req model.RefundUnifiedReq) (*model.RefundResp, error) {
	bm := make(gopay.BodyMap)
	bm.Set("out_trade_no", req.OutTradeNo).
		Set("out_request_no", req.OutRefundNo).
		Set("refund_amount", formatAmount(req.RefundPrice)).
		Set("refund_reason", req.Reason)
	resp, err := a.client.TradeRefund(ctx, bm)
	if err != nil {
		return nil, err
	}
	if resp.Response.SubCode != "" {
		if resp.Response.SubCode == "ACQ.SYSTEM_ERROR" || resp.Response.SubCode == "SYSTEM_ERROR" {
			return &model.RefundResp{
				Status:      model.WAITING,
				OutRefundNo: req.OutRefundNo,
				RawData:     resp.Response,
			}, nil
		}
		return &model.RefundResp{
			Status:           model.ERROR,
			ChannelErrorCode: resp.Response.SubCode,
			ChannelErrorMsg:  resp.Response.SubMsg,
			OutRefundNo:      req.OutRefundNo,
			RawData:          resp.Response,
		}, nil
	}
	// 支付宝只要退款调用返回 success，就认为退款成功，不需要回调。
	// 支付宝退款时，没有回调，这点和微信支付是不同的。并且，退款分成部分退款、和全部退款。
	// ① 部分退款：是会有回调，但是它回调的是订单状态的同步回调，不是退款订单的回调
	// ② 全部退款：Wap 支付有订单状态的同步回调，但是 PC/扫码又没有
	// 所以，这里在解析时，即使是退款导致的订单状态同步，我们也忽略不做为“退款同步”，而是订单的回调。
	// 实际上，支付宝退款只要发起成功，就可以认为退款成功，不需要等待回调。
	// 另外，支付宝没有退款单号，所以不用设置
	return &model.RefundResp{
		Status:      model.SUCCESS,
		SuccessTime: model.ParseDate(resp.Response.GmtRefundPay),
		OutRefundNo: req.OutRefundNo,
		RawData:     resp.Response,
	}, nil
}

func formatAmount(amount int32) string {
	return fmt.Sprintf("%.2f", float64(amount)/100.0)
}

func parseStatus(tradeStatus string) *uint8 {
	switch tradeStatus {
	case "WAIT_BUYER_PAY":
		status := model.WAITING
		return &status
	case "TRADE_FINISHED", "TRADE_SUCCESS":
		status := model.SUCCESS
		return &status
	case "TRADE_CLOSED":
		status := model.CLOSED
		return &status
	default:
		return nil
	}
}

func ParseAliClientConfig(config string) (model.ClientConfig, error) {
	var aliClientConfig ClientConfig
	err := json.Unmarshal([]byte(config), &aliClientConfig)
	if err != nil {
		return nil, err
	}
	return aliClientConfig, nil
}
