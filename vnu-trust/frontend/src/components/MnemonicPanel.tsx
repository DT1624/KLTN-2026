import { useMemo, useState } from "react";
import { pickVerificationIndices } from "../lib/mnemonic";
import { Alert } from "./ui";

/** Chỉ báo bước của quy trình thật: vòng số, bước hiện tại chữ xanh đậm. */
function Steps({ current }: { current: 1 | 2 | 3 }) {
  const steps = ["Chép 12 từ", "Xác nhận", "Vào hệ thống"];
  return (
    <ol className="flex flex-wrap gap-x-6 gap-y-2 text-sm" aria-label="Các bước">
      {steps.map((s, i) => (
        <li key={s} aria-current={current === i + 1 ? "step" : undefined}
          className={`flex items-center gap-2 ${
            current === i + 1 ? "text-primary font-semibold" : "text-ink-2"
          }`}>
          <span className="grid place-items-center w-6 h-6 rounded-chip bg-primary-soft text-primary text-xs font-semibold tabular-nums">
            {i + 1}
          </span>
          {s}
        </li>
      ))}
    </ol>
  );
}

/**
 * Hiển thị 12 từ đúng MỘT lần ngay sau khi tạo ví, rồi bắt người dùng nhập lại
 * vài từ để chắc chắn họ đã chép. Không lưu cụm từ ở đâu cả — đóng màn hình này
 * là mất, đúng như thiết kế.
 */
export default function MnemonicPanel({
  mnemonic,
  onConfirmed,
}: {
  mnemonic: string;
  onConfirmed: () => void;
}) {
  const words = useMemo(() => mnemonic.split(" "), [mnemonic]);
  const quiz = useMemo(() => pickVerificationIndices(3, words.length), [words.length]);
  const [answers, setAnswers] = useState<Record<number, string>>({});
  const [revealed, setRevealed] = useState(false);
  const [stage, setStage] = useState<"show" | "verify">("show");
  const [err, setErr] = useState("");

  const allCorrect = quiz.every(
    (i) => (answers[i] ?? "").trim().toLowerCase() === words[i],
  );

  if (stage === "show") {
    return (
      <div className="space-y-4">
        <Steps current={1} />
        <Alert tone="warn" title="Chép 12 từ này ra giấy ngay bây giờ">
          Đây là cách <strong>duy nhất</strong> để đăng nhập tài khoản này trên máy khác, hoặc
          lấy lại ví nếu mất thiết bị. Chúng tôi không lưu cụm từ này ở bất kỳ đâu. Đóng
          màn hình là mất vĩnh viễn. Đừng chụp màn hình, đừng lưu vào máy tính.
        </Alert>

        <div className="relative">
          <ol
            className={`sheet grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-3 p-5 ${
              revealed ? "" : "blur-sm select-none"
            }`}
          >
            {words.map((w, i) => (
              <li key={i} className="flex items-baseline gap-2">
                <span className="text-sm tabular-nums text-muted w-6 shrink-0">{i + 1}</span>
                <span className="text-base font-semibold">{w}</span>
              </li>
            ))}
          </ol>
          {!revealed && (
            <button
              type="button"
              onClick={() => setRevealed(true)}
              className="absolute inset-0 grid place-items-center rounded-sheet"
            >
              <span className="btn-secondary">Bấm để hiện 12 từ</span>
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            className="btn-quiet"
            disabled={!revealed}
            onClick={() => navigator.clipboard?.writeText(mnemonic)}
          >
            Sao chép tạm thời
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={!revealed}
            onClick={() => setStage("verify")}
          >
            Tôi đã chép xong
          </button>
        </div>
      </div>
    );
  }

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        if (!allCorrect) {
          setErr("Có từ chưa đúng. Kiểm tra lại bản chép của bạn.");
          return;
        }
        onConfirmed();
      }}
    >
      <Steps current={2} />
      <Alert tone="info" title="Xác nhận bạn đã chép đúng">
        Nhập lại {quiz.length} từ dưới đây theo đúng số thứ tự.
      </Alert>

      <div className="grid sm:grid-cols-3 gap-3">
        {quiz.map((i) => (
          <div key={i}>
            <label className="label" htmlFor={`w${i}`}>
              Từ số {i + 1}
            </label>
            <input
              id={`w${i}`}
              className="input"
              autoComplete="off"
              spellCheck={false}
              value={answers[i] ?? ""}
              onChange={(e) => setAnswers({ ...answers, [i]: e.target.value })}
            />
          </div>
        ))}
      </div>

      {err && <Alert tone="bad">{err}</Alert>}

      <div className="flex flex-wrap gap-3">
        <button type="button" className="btn-secondary" onClick={() => setStage("show")}>
          Xem lại 12 từ
        </button>
        <button className="btn-primary" disabled={!allCorrect}>
          Xác nhận và vào hệ thống
        </button>
      </div>
    </form>
  );
}
