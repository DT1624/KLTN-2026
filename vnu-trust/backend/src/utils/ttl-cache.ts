/**
 * Bộ nhớ đệm sống rất ngắn, dùng cho những giá trị tổng hợp đắt đỏ mà không
 * cần tươi từng mili giây.
 *
 * Lý do có tệp này: tuyến `/stats` của trang chủ gọi bốn phép tổng hợp riêng
 * biệt (số admin, số issuer, số DID, số VC). Ở chế độ on-chain đó là bốn vòng
 * gọi fullnode cho MỖI lượt xem trang; ở chế độ đọc CSDL thì vẫn là nhiều lượt
 * truy vấn lặp lại. Một bộ đếm trên trang chủ chậm vài giây không sao, nhưng
 * làm fullnode nghẹn thì có.
 *
 * Gộp cả các lượt gọi song song vào chung một lần tính: nếu 50 người mở trang
 * cùng lúc lúc đệm vừa hết hạn thì chỉ đúng một phép tính chạy.
 */
export function ttlCache<T>(ttlMs: number, compute: () => Promise<T>): () => Promise<T> {
  let value: T | undefined;
  let expiresAt = 0;
  let inflight: Promise<T> | null = null;

  return async () => {
    if (value !== undefined && Date.now() < expiresAt) return value;
    if (inflight) return inflight;

    inflight = compute()
      .then((v) => {
        value = v;
        expiresAt = Date.now() + ttlMs;
        return v;
      })
      .finally(() => {
        inflight = null;
      });
    return inflight;
  };
}
