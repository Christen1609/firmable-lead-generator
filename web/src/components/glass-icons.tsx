"use client";

import type { CSSProperties, ReactNode } from "react";
import "./glass-icons.css";

/**
 * React Bits — GlassIcons.
 *
 * The stock palette is bright blue/purple/red, which fights this app's
 * monochrome editorial theme, so the mapping below is keyed to the colours the
 * design already uses: near-black for ordinary findings, the tier red for
 * anything confirmed exploited. Any raw CSS colour or gradient still works.
 */
const gradientMapping: Record<string, string> = {
  ink: "linear-gradient(#3a3a38, #1a1a1a)",
  critical: "linear-gradient(#c9372b, #8f1a11)",
  stone: "linear-gradient(#8e8e8b, #636260)",
  blue: "linear-gradient(hsl(223, 90%, 50%), hsl(208, 90%, 50%))",
  purple: "linear-gradient(hsl(283, 90%, 50%), hsl(268, 90%, 50%))",
  red: "linear-gradient(hsl(3, 90%, 50%), hsl(348, 90%, 50%))",
  indigo: "linear-gradient(hsl(253, 90%, 50%), hsl(238, 90%, 50%))",
  orange: "linear-gradient(hsl(43, 90%, 50%), hsl(28, 90%, 50%))",
  green: "linear-gradient(hsl(123, 90%, 40%), hsl(108, 90%, 40%))",
};

function backgroundFor(color: string): CSSProperties {
  return { background: gradientMapping[color] ?? color };
}

export interface GlassIconsItem {
  icon: ReactNode;
  color: string;
  label: string;
  customClass?: string;
}

interface GlassIconsProps {
  items: GlassIconsItem[];
  className?: string;
}

export function GlassIcons({ items, className }: GlassIconsProps) {
  return (
    <div className={`icon-btns ${className ?? ""}`}>
      {items.map((item, index) => (
        <button
          key={index}
          className={`icon-btn ${item.customClass ?? ""}`}
          aria-label={item.label}
          type="button"
        >
          <span className="icon-btn__back" style={backgroundFor(item.color)} />
          <span className="icon-btn__front">
            <span className="icon-btn__icon" aria-hidden="true">
              {item.icon}
            </span>
          </span>
          <span className="icon-btn__label">{item.label}</span>
        </button>
      ))}
    </div>
  );
}

interface GlassTileProps {
  children: ReactNode;
  /** Key from the gradient map above, or any raw CSS colour/gradient. */
  color?: string;
  /** Tile edge length, as a CSS length. */
  size?: string;
  radius?: string;
  /** Foreground colour for the tile contents. */
  foreground?: string;
  label?: string;
}

/**
 * A single non-interactive GlassIcons tile, for use inside a card that already
 * carries its own click target — the numbered badges on the findings list.
 * Same three-layer construction as GlassIcons: tinted back plate, frosted
 * front, contents on top.
 */
export function GlassTile({
  children,
  color = "ink",
  size = "3.25em",
  radius = "0.95em",
  foreground = "#faf9f7",
  label,
}: GlassTileProps) {
  return (
    <span
      className="icon-btn"
      style={
        {
          display: "inline-block",
          "--glass-size": size,
          "--glass-radius": radius,
          "--glass-fg": foreground,
        } as CSSProperties
      }
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      <span className="icon-btn__back" style={backgroundFor(color)} />
      <span className="icon-btn__front">
        <span className="icon-btn__icon">{children}</span>
      </span>
    </span>
  );
}

export default GlassIcons;
