package weixin

import (
	"context"
	"github.com/agui-coder/simple-admin-pay-common/payment/model"
	"github.com/go-pay/gopay/wechat/v3"
	"github.com/suyuan32/simple-admin-common/utils/pointy"
	"github.com/zeromicro/go-zero/core/errorx"
	"github.com/zeromicro/go-zero/core/logx"
)

// NativePayClient 结构体继承了 Client 接口
type NativePayClient struct {
	Client
}

// 编译时接口实现的检查
var _ model.Client = (*NativePayClient)(nil)

func NewWxNativePayClient(channelId uint64, config model.ClientConfig) model.Client {
	wxConfig, ok := config.(ClientConfig)
	if !ok {
		logx.Error("config is not of type weixin.ClientConfig")
		return nil
	}
	return &NativePayClient{
		Client{Config: &wxConfig, ChannelId: channelId},
	}
}

func (w *NativePayClient) UnifiedOrder(ctx context.Context, req model.OrderUnifiedReq) (*model.OrderResp, error) {
	bm := w.buildPayUnifiedOrderBm(req)
	wxRsp, err := w.client.V3TransactionNative(ctx, bm)
	if err != nil {
		logx.Error(err)
		return nil, err
	}
	if wxRsp.Code == wechat.Success {
		return model.WaitingOf(pointy.GetPointer(model.QrCode),
			pointy.GetPointer(wxRsp.Response.CodeUrl), req.OutTradeNo,
			wxRsp.Response.CodeUrl), nil
	}
	logx.Errorf("wxRsp:%s", wxRsp.Error)
	return nil, errorx.NewInvalidArgumentError(wxRsp.Error)
}
