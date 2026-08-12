import { TIER_BADGE_STYLES } from "@/lib/constants";

interface TierBadgeProps {
  tier: string | null;
  className?: string;
}

export function TierBadge({ tier, className }: TierBadgeProps) {
  if (!tier) return null;
  const style = TIER_BADGE_STYLES[tier] ?? TIER_BADGE_STYLES.Low;
  return (
    <span
      className={className}
      style={{
        ...style,
        display: "inline-flex",
        alignItems: "center",
        lineHeight: 1,
        borderRadius: 999,
        fontWeight: 600,
        whiteSpace: "nowrap",
        padding: "6px 14px",
        fontSize: 12,
      }}
    >
      {tier}
    </span>
  );
}
