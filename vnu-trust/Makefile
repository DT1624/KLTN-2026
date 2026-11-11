# VNU-Trust — lệnh thường dùng. Gõ `make` để xem danh sách.
.DEFAULT_GOAL := help
SH := ./scripts
NPM_CACHE ?= /tmp/vnu-trust-npm-cache

.PHONY: help install build up up-ts up-go down restart status \
        db db-shell test test-quick bench bench-report clean clean-all sync-env deploy-contract chain-probe

help: ## Danh sách lệnh
	@grep -hE '^[a-z%-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36mmake %-15s\033[0m %s\n", $$1, $$2}'

install: ## Cài phụ thuộc cho backend TS, frontend và tải module Go
	cd backend && npm ci --cache $(NPM_CACHE)
	cd frontend && npm ci --cache $(NPM_CACHE)
	cd backend-go && go mod download

build: ## Build cả ba thành phần (kiểm tra biên dịch được)
	cd backend && npm run build
	cd backend-go && go build -o bin/server ./cmd/server
	cd frontend && npm run build

up: ## Bật cả hệ thống: Postgres + backend TS + backend Go + giao diện
	@$(SH)/dev.sh up all

up-ts: ## Chỉ chạy backend TypeScript (kèm Postgres và giao diện)
	@$(SH)/dev.sh up db && $(SH)/dev.sh up ts && $(SH)/dev.sh up ui

up-go: ## Chỉ chạy backend Go (kèm Postgres và giao diện)
	@$(SH)/dev.sh up db && $(SH)/dev.sh up go && $(SH)/dev.sh up ui

down: ## Tắt mọi thành phần (giữ volume dữ liệu)
	@$(SH)/dev.sh down all

restart: ## Tắt rồi bật lại toàn bộ (nạp lại .env)
	@$(SH)/dev.sh restart all

status: ## Xem thành phần nào đang chạy
	@$(SH)/dev.sh status

logs-%: ## Theo dõi log: make logs-ts | logs-go | logs-ui
	@$(SH)/dev.sh logs $*

db: ## Chỉ bật Postgres
	@$(SH)/dev.sh up db

db-shell: ## Mở psql vào CSDL dev
	docker exec -it vnu_trust_postgres psql -U vnu_trust vnu_trust

test: ## Toàn bộ kiểm thử trên CSDL + cổng riêng, xong tự dọn
	@$(SH)/test.sh

test-quick: ## Chỉ kiểm thử tĩnh (Move, ABI, typecheck, go test) — không cần CSDL
	@$(SH)/test.sh --quick

bench: ## Đo hiệu năng nhanh hai backend
	@$(SH)/bench.sh

bench-report: ## Bộ đo mở rộng cho báo cáo → .bench/tex
	@$(SH)/bench.sh --report

clean: ## Dừng hết, xoá log/tệp tạm/build (giữ dữ liệu, image, node_modules)
	@$(SH)/clean.sh

clean-all: ## Như clean + xoá volume dữ liệu và node_modules (có hỏi)
	@$(SH)/clean.sh --all

sync-env: ## Đẩy chain.env sang ba tệp .env
	@$(SH)/sync-chain-env.sh

chain-probe: ## Mô phỏng giao dịch với fullnode thật (không ghi lên chuỗi)
	node frontend/scripts/chain-probe.mjs

deploy-contract: ## Publish lại hợp đồng (hỏi xác nhận, tạo hiện vật công khai)
	@$(SH)/deploy.sh
