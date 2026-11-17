// Bộ biểu tượng nét đơn giản trên lưới 16 px; màu theo currentColor.
import type { ReactNode } from "react";

interface IconProps {
  className?: string;
}

function Base({ className, children }: IconProps & { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={className ?? "w-4 h-4"}
    >
      {children}
    </svg>
  );
}

export function IconCheck({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M3 8.5l3.2 3.2L13 4.8" />
    </Base>
  );
}

export function IconCross({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M4 4l8 8M12 4l-8 8" />
    </Base>
  );
}

export function IconPause({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M5.5 3.5v9M10.5 3.5v9" />
    </Base>
  );
}

export function IconAlert({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M8 2.5L14 13H2L8 2.5z" />
      <path d="M8 6.5v3M8 11.6v.1" />
    </Base>
  );
}

export function IconInfo({ className }: IconProps) {
  return (
    <Base className={className}>
      <circle cx="8" cy="8" r="6" />
      <path d="M8 7.2v3.6M8 4.9v.1" />
    </Base>
  );
}

export function IconCopy({ className }: IconProps) {
  return (
    <Base className={className}>
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
      <path d="M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2" />
    </Base>
  );
}

export function IconExternal({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M9.5 2.5h4v4M13.5 2.5L7.5 8.5" />
      <path d="M12 9.5v3a1 1 0 0 1-1 1H3.5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h3" />
    </Base>
  );
}

export function IconMenu({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />
    </Base>
  );
}

export function IconClose({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" />
    </Base>
  );
}

export function IconLock({ className }: IconProps) {
  return (
    <Base className={className}>
      <rect x="3" y="7" width="10" height="6.5" rx="1.5" />
      <path d="M5.2 7V5.2a2.8 2.8 0 0 1 5.6 0V7" />
    </Base>
  );
}

export function IconChevronLeft({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M10 3.5L5.5 8l4.5 4.5" />
    </Base>
  );
}

export function IconChevronRight({ className }: IconProps) {
  return (
    <Base className={className}>
      <path d="M6 3.5L10.5 8 6 12.5" />
    </Base>
  );
}
