# Backend Go — P7 (13/11/2026). Chỉ thị `toolchain` trong go.mod quyết định bản Go thật.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
EXPOSE 4001
ENTRYPOINT ["/server"]
