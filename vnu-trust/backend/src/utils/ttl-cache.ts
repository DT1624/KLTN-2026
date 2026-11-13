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

/**
 * Đệm sống ngắn THEO KHOÁ (P5, 13/11/2026) — cùng hành vi gộp lượt gọi song song như
 * ttlCache, nhưng mỗi khoá một giá trị. Phải khớp backend Go (handlers/ttlcache.go).
 * Chỉ dùng cho câu hỏi chấp nhận được độ trễ vài giây; KHÔNG dùng cho phép kiểm trạng
 * thái chống phát lại (quyết định #19).
 */
export function ttlKeyed<V>(ttlMs: number, compute: (key: string) => Promise<V>): (key: string) => Promise<V> {
  const values = new Map<string, { v: V; at: number }>();
  const inflight = new Map<string, Promise<V>>();
  return async (key: string) => {
    const hit = values.get(key);
    if (hit && Date.now() - hit.at < ttlMs) return hit.v;
    const running = inflight.get(key);
    if (running) return running;
    const p = compute(key)
      .then((v) => {
        if (values.size > 10_000) values.clear(); // chặn phình bộ nhớ, đơn giản và đủ
        values.set(key, { v, at: Date.now() });
        return v;
      })
      .finally(() => inflight.delete(key));
    inflight.set(key, p);
    return p;
  };
}

/** Chạy `fn` cho từng phần tử với tối đa `limit` lượt song song; giữ nguyên thứ tự kết quả. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (x: T, i: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!, i);
    }
  }));
  return out;
}
