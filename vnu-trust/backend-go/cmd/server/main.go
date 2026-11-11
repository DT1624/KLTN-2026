// Lệnh server khởi động backend Go của VNU-Trust.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vnu-trust/backend-go/internal/chain"
	"github.com/vnu-trust/backend-go/internal/config"
	"github.com/vnu-trust/backend-go/internal/db"
	"github.com/vnu-trust/backend-go/internal/handlers"
	"github.com/vnu-trust/backend-go/internal/middleware"
	"github.com/vnu-trust/backend-go/internal/services"
)

func main() {
	if err := run(); err != nil {
		slog.Error("khởi động thất bại", "err", err)
		os.Exit(1)
	}
}

func run() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	database, err := db.Open(ctx, cfg.DSN())
	if err != nil {
		return fmt.Errorf("mở kết nối Postgres: %w", err)
	}
	defer database.Close()
	if err := database.WaitReady(ctx, 20, 2*time.Second); err != nil {
		return fmt.Errorf("Postgres không sẵn sàng: %w", err)
	}

	chainClient := chain.New(cfg)
	// VERIFY_ONCHAIN=false: trả lời câu hỏi quyền/DID bằng chỉ mục CSDL để
	// chạy được khi chưa có chuỗi. Xem internal/chain/offline.go.
	chainClient.UseOfflineSource(database.Pool)

	if chainClient.Offline() {
		slog.Warn("CHẠY KHÔNG PHỤ THUỘC CHUỖI (VERIFY_ONCHAIN=false) — chỉ dùng để phát triển/kiểm thử")
	} else if h, err := chainClient.Health(ctx); err != nil {
		// Không chặn khởi động: các tuyến không phụ thuộc chuỗi vẫn chạy được.
		slog.Error("không kết nối được fullnode — các tính năng on-chain sẽ lỗi", "err", err)
	} else {
		slog.Info("đã kết nối fullnode", "chainId", h.ChainID,
			"ledgerVersion", h.LedgerVersion, "contract", cfg.ContractAddress)
	}

	store := services.NewStore(database)
	ipfs := services.NewIPFS(cfg, database.Pool)
	api := handlers.New(cfg, store, chainClient, ipfs)

	// Giữ đúng tỉ lệ bùng phát 5:1 như trước khi hạn mức được đưa ra cấu hình,
	// để đổi RATE_LIMIT_PER_MIN không vô tình nới luôn mức bùng phát.
	burst := cfg.RateLimitPerMin / 5
	if burst < 1 {
		burst = 1
	}
	limiter := middleware.NewRateLimiter(cfg.RateLimitPerMin, burst)
	handler := middleware.SecurityHeaders(
		middleware.CORS(cfg.FrontendOrigin,
			middleware.Logger(limiter.Wrap(api.Routes()))))

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Dọn challenge hết hạn định kỳ để bảng không phình vô hạn.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := store.PurgeExpiredChallenges(ctx); err != nil {
					slog.Warn("dọn challenge lỗi", "err", err)
				} else if n > 0 {
					slog.Info("đã dọn challenge hết hạn", "số", n)
				}
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("VNU-Trust backend (Go) đang chạy", "url", fmt.Sprintf("http://localhost:%d", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("nhận tín hiệu dừng, đang tắt...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
