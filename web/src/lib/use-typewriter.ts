"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Reveals text one character at a time.
 *
 * Used for the call hook, where the point is that the salesperson reads along
 * at roughly speaking pace rather than being handed a wall of text.
 *
 * Honours prefers-reduced-motion by showing the full string immediately — a
 * character-by-character reveal is exactly the kind of motion that setting is
 * asking us to skip, and the content is the same either way.
 */
export function useTypewriter(text: string, charsPerSecond = 45) {
  const [revealed, setRevealed] = useState("");
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    if (!text) {
      setRevealed("");
      return;
    }

    const reduceMotion =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reduceMotion) {
      setRevealed(text);
      return;
    }

    // Driven by elapsed time rather than a per-character timer, so the pace
    // holds steady if a frame is dropped and the whole string always lands.
    const startedAt = performance.now();
    const step = (now: number) => {
      const elapsedSeconds = (now - startedAt) / 1000;
      const count = Math.floor(elapsedSeconds * charsPerSecond);
      if (count >= text.length) {
        setRevealed(text);
        return;
      }
      setRevealed(text.slice(0, count));
      frameRef.current = requestAnimationFrame(step);
    };
    frameRef.current = requestAnimationFrame(step);

    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
    };
  }, [text, charsPerSecond]);

  return { revealed, isTyping: revealed.length < text.length };
}
