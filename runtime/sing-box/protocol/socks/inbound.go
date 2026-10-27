package socks

import (
	std_bufio "bufio"
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/common/userstate"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SocksInboundOptions](registry, C.TypeSOCKS, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router      adapter.ConnectionRouterEx
	logger      logger.ContextLogger
	listener    *listener.Listener
	users       atomic.Pointer[userSnapshot]
	userManager *userstate.Manager
	userTable   *userstate.Table
	udpTimeout  time.Duration
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SocksInboundOptions) (adapter.Inbound, error) {
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	inbound := &Inbound{
		Adapter:    inbound.NewAdapter(C.TypeSOCKS, tag),
		router:     uot.NewRouter(router, logger),
		logger:     logger,
		udpTimeout: udpTimeout,
	}
	inbound.userManager = userstate.FromContext(ctx)
	inbound.userTable = inbound.userManager.NewTable()
	publish, err := inbound.prepareUsers(&options, nil)
	if err != nil {
		return nil, err
	}
	inbound.userManager.Commit(publish)
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	_ = h.userTable.Close()
	return h.listener.Close()
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	snapshot := h.users.Load()
	// Keep explicit anonymous inbounds compatible. An authenticated inbound never
	// becomes anonymous when its final account is removed.
	if snapshot.authenticator == nil && snapshot.required {
		N.CloseOnHandshakeFailure(conn, onClose, userstate.ErrRevoked)
		return
	}
	if snapshot.authenticator == nil {
		err := socks.HandleConnectionEx(ctx, conn, std_bufio.NewReader(conn), nil, adapter.NewUpstreamHandlerEx(metadata, h.newUserConnection, h.streamUserPacketConnection), h.listener, h.udpTimeout, metadata.Source, onClose)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	ctx, session := h.userManager.NewSession(ctx, conn)
	conn = session
	ctx = context.WithValue(ctx, snapshotKey{}, snapshot)
	previousClose := onClose
	onClose = N.OnceClose(func(err error) {
		_ = session.Close()
		if previousClose != nil {
			previousClose(err)
		}
	})
	err := socks.HandleConnectionEx(ctx, conn, std_bufio.NewReader(conn), snapshot.authenticator, adapter.NewUpstreamHandlerEx(metadata, h.newUserConnection, h.streamUserPacketConnection), userPacketListener{h}, h.udpTimeout, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if ctx.Value(snapshotKey{}) != nil {
		if err := bindUser(ctx); err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) streamUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if ctx.Value(snapshotKey{}) != nil {
		if err := bindUser(ctx); err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		if !metadata.Destination.IsValid() {
			h.logger.InfoContext(ctx, "inbound packet connection")
		} else {
			h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		}
		h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	if !metadata.Destination.IsValid() {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
