"use client";

import { useMemo } from "react";
import { LAND_ROWS, MAP } from "@/lib/worldDots";
import type { Count } from "@/lib/types";
import { num } from "@/lib/format";

/** Rough country centres [longitude, latitude] for placing hotspots. */
const CENTRES: Record<string, [number, number]> = {
  "United States": [-98, 39], Canada: [-104, 57], Mexico: [-102, 23], Brazil: [-52, -10], Argentina: [-64, -34],
  "United Kingdom": [-2, 54], France: [2, 47], Germany: [10, 51], Netherlands: [5.5, 52.2], Spain: [-4, 40],
  Italy: [12.5, 42.8], Poland: [19, 52], Sweden: [16, 62], Ukraine: [31, 49], Romania: [25, 46], Turkey: [35, 39],
  Russia: [96, 61], Iran: [53, 32], India: [79, 22], Pakistan: [69, 30], Bangladesh: [90, 24],
  China: [104, 35], "Hong Kong": [114.2, 22.3], Taiwan: [121, 23.7], Japan: [138, 37], "South Korea": [128, 36],
  Vietnam: [106, 16], Thailand: [101, 15], Singapore: [103.8, 1.35], Indonesia: [117, -2], Philippines: [122, 12],
  Australia: [134, -25], "South Africa": [24, -29], Nigeria: [8, 9.5], Egypt: [30, 27],
};

const CELL = 6;

function decode(): string {
  let d = "";
  LAND_ROWS.forEach((row, r) => {
    let c = 0, land = false;
    for (const run of row.split(".")) {
      const n = parseInt(run, 36);
      if (land) for (let k = 0; k < n; k++) d += `M${(c + k) * CELL + CELL / 2},${r * CELL + CELL / 2}h0`;
      c += n;
      land = !land;
    }
  });
  return d;
}

const project = ([lon, lat]: [number, number]) => ({
  x: ((lon + 180) / MAP.step) * CELL,
  y: ((MAP.latMax - lat) / MAP.step) * CELL,
});

export function WorldMap({ countries }: { countries: Count[] }) {
  const land = useMemo(decode, []);
  const placed = countries.filter((c) => CENTRES[String(c.key)]);
  const max = Math.max(1, ...placed.map((c) => c.count));
  const unplaced = countries.filter((c) => !CENTRES[String(c.key)]);
  const w = MAP.cols * CELL, h = MAP.rows * CELL;

  return (
    <div>
      <svg
        viewBox={`0 0 ${w} ${h}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Alert sources on a world map: ${countries.map((c) => `${c.key} ${num(c.count)}`).join(", ")}`}
      >
        <defs>
          <radialGradient id="hot">
            <stop offset="0%" stopColor="var(--signal)" stopOpacity="0.55" />
            <stop offset="60%" stopColor="var(--signal)" stopOpacity="0.18" />
            <stop offset="100%" stopColor="var(--signal)" stopOpacity="0" />
          </radialGradient>
        </defs>
        <path d={land} stroke="var(--ink-3)" strokeOpacity={0.38} strokeWidth={2.8} strokeLinecap="round" />
        {placed.map((c) => {
          const p = project(CENTRES[String(c.key)]);
          const r = 10 + 34 * Math.sqrt(c.count / max);
          return (
            <g key={String(c.key)}>
              <title>{`${c.key}: ${num(c.count)} alerts`}</title>
              <circle cx={p.x} cy={p.y} r={r} fill="url(#hot)" />
              <circle cx={p.x} cy={p.y} r={4.5} fill="var(--signal-strong)" stroke="var(--surface)" strokeWidth={1.5} />
            </g>
          );
        })}
      </svg>
      {unplaced.length > 0 && (
        <p className="mt-1 text-[12px] text-ink-3">
          Not on the map: {unplaced.map((c) => `${c.key} (${num(c.count)})`).join(", ")}
        </p>
      )}
    </div>
  );
}
