import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    // Thang cỡ chữ bản 2 (xem frontend/DESIGN.md): ghi đè hoàn toàn thang mặc định.
    fontSize: {
      xs: ["12px", { lineHeight: "16px" }],
      sm: ["14px", { lineHeight: "20px" }],
      base: ["16px", { lineHeight: "24px" }],
      lg: ["18px", { lineHeight: "26px" }],
      xl: ["20px", { lineHeight: "28px" }],
      "2xl": ["24px", { lineHeight: "32px" }],
      "3xl": ["32px", { lineHeight: "40px" }],
      "4xl": ["40px", { lineHeight: "48px" }],
      "5xl": ["48px", { lineHeight: "56px" }],
    },
    extend: {
      colors: {
        primary: { DEFAULT: "#034EA1", hover: "#023A7A", soft: "#E8F1FB", soft2: "#D4E5F7" },
        ink: { DEFAULT: "#0F172A", 2: "#334155", hover: "#023A7A" },
        muted: "#64748B",
        subtle: "#94A3B8",
        paper: "#F8FAFC",
        sheet: "#FFFFFF",
        tint: "#EEF2F7",
        rule: "#E2E8F0",
        pencil: "#CBD5E1",
        success: { DEFAULT: "#15803D", soft: "#DCFCE7" },
        warning: { DEFAULT: "#C2410C", soft: "#FFEDD5" },
        son: { DEFAULT: "#B91C1C", dark: "#991B1B", tint: "#FEE2E2" },
        mark: { DEFAULT: "#FFB606", soft: "#FFF4D6" },
        vnu: "#038141",
      },
      fontFamily: {
        sans: ['"Inter Tight Variable"', '"Inter Tight"', "system-ui", "-apple-system", '"Segoe UI"', "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", '"Liberation Mono"', "monospace"],
      },
      borderRadius: {
        ctrl: "6px",
        sheet: "10px",
        lg2: "16px",
        chip: "999px",
      },
      boxShadow: {
        card: "0 1px 2px rgba(15,23,42,.04)",
        raised: "0 2px 12px rgba(15,23,42,.06)",
      },
    },
  },
  plugins: [],
} satisfies Config;
