// Hoa văn đối chiếu sinh từ chuỗi hạt giống (xem lib/rosette.ts).
// Lớp CSS khi animate (định nghĩa ở index.css):
//   .rosette-draw path { stroke-dasharray:1; stroke-dashoffset:1;
//     animation: rosette-draw 1.1s cubic-bezier(.4,0,.2,1) forwards }
//   @keyframes rosette-draw { to { stroke-dashoffset: 0 } }
import { useMemo } from "react";
import { rosettePaths } from "../lib/rosette";

export default function Rosette({
  seed,
  size = 96,
  title,
  animate = false,
  className = "",
}: {
  seed: string;
  size?: number;
  title?: string;
  animate?: boolean;
  className?: string;
}) {
  const detail = size >= 160 ? 1 : size >= 64 ? 0.6 : 0.35;
  const paths = useMemo(() => rosettePaths(seed, detail), [seed, detail]);

  // Dưới 24 px các nét mảnh thành vệt mờ, không còn nhận ra hoa văn: không vẽ.
  if (size < 24) return null;

  // Nhỏ thì làm dày nét để còn thấy.
  const scale = Math.max(1, 120 / size);
  const a11y = title ? { role: "img" as const, "aria-label": title } : { "aria-hidden": true as const };

  return (
    <svg
      viewBox="0 0 240 240"
      width={size}
      height={size}
      className={"text-primary shrink-0 " + (animate ? "rosette-draw " : "") + className}
      {...a11y}
    >
      <g fill="none" stroke="currentColor">
        {paths.map((p, i) => (
          <path key={i} d={p.d} pathLength={1} strokeWidth={p.w * scale} strokeOpacity={p.o} />
        ))}
      </g>
    </svg>
  );
}
