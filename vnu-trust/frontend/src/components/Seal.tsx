// Dấu tròn xanh lá (màu logo ĐHQGHN) "đã xác minh trên chuỗi". Không mô phỏng con dấu thật của ĐHQGHN.
// Lớp CSS khi animate (keyframes định nghĩa ở index.css):
//   .seal-stamp { animation: seal-stamp .42s cubic-bezier(.2,.9,.3,1.25) 1.05s both }
//   @keyframes seal-stamp {
//     0%   { opacity:0; transform: rotate(-12deg) scale(1.4) }
//     65%  { opacity:1; transform: rotate(-12deg) scale(.96) }
//     100% { opacity:1; transform: rotate(-12deg) scale(1) }
//   }
// Xoay -12 độ đặt tĩnh bằng style; keyframes ghi đè transform khi chạy.
import { useId } from "react";

export default function Seal({
  size = 120,
  animate = false,
  className = "",
}: {
  size?: number;
  animate?: boolean;
  className?: string;
}) {
  const uid = useId().replace(/:/g, "");
  const ringId = `seal-ring-${uid}`;
  const filterId = `seal-ink-${uid}`;

  return (
    <svg
      viewBox="0 0 200 200"
      width={size}
      height={size}
      aria-hidden="true"
      focusable="false"
      className={"text-vnu shrink-0 " + (animate ? "seal-stamp " : "") + className}
      style={{ mixBlendMode: "multiply", transform: "rotate(-12deg)" }}
    >
      <defs>
        <filter id={filterId} x="-5%" y="-5%" width="110%" height="110%">
          <feTurbulence type="fractalNoise" baseFrequency="0.045" numOctaves={2} seed={7} result="n" />
          <feDisplacementMap in="SourceGraphic" in2="n" scale={2.6} />
        </filter>
        <path id={ringId} d="M100,100 m-73,0 a73,73 0 1,1 146,0 a73,73 0 1,1 -146,0" />
      </defs>
      <g filter={`url(#${filterId})`} color="#038141">
        <circle cx="100" cy="100" r="94" fill="none" stroke="currentColor" strokeWidth={5} />
        <circle cx="100" cy="100" r="86" fill="none" stroke="currentColor" strokeWidth={1.4} />
        <circle cx="100" cy="100" r="56" fill="none" stroke="currentColor" strokeWidth={1.4} />
        <text
          fill="currentColor"
          fontFamily='"Inter Tight Variable", "Inter Tight", sans-serif'
          fontWeight={700}
          fontSize={15}
        >
          <textPath href={`#${ringId}`} textLength={452} lengthAdjust="spacing">
            VNU-TRUST ✦ ĐÃ XÁC MINH TRÊN CHUỖI ✦
          </textPath>
        </text>
        <path d="M78 101l14 14 30-32" fill="none" stroke="currentColor" strokeWidth={7} strokeLinecap="square" />
      </g>
    </svg>
  );
}
