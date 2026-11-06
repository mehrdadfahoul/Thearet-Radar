import React from 'react';
import { Radio, AlertTriangle, ShieldCheck, Flame } from 'lucide-react';
import { TickerItem } from '../types';

interface TickerProps {
  items: TickerItem[];
  onSelectCve?: (cveId: string) => void;
}

export const Ticker: React.FC<TickerProps> = ({ items, onSelectCve }) => {
  if (!items || items.length === 0) return null;

  // Duplicate items array to make infinite marquee seamless
  const displayItems = [...items, ...items];

  return (
    <div className="relative overflow-hidden bg-[#0a0512] border-b border-rose-900/40 text-slate-200 py-2">
      <div className="flex items-center">
        {/* Ticker Lead Tag */}
        <div className="z-10 bg-gradient-to-r from-rose-900 to-rose-950 px-3 py-1 flex items-center gap-1.5 text-xs font-bold font-mono text-rose-300 border-r border-rose-800 shadow-md flex-shrink-0">
          <Flame className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
          <span className="tracking-wider">ACTIVE ZERO-DAYS TICKER</span>
        </div>

        {/* Marquee Container */}
        <div className="overflow-hidden whitespace-nowrap flex w-full relative">
          <div className="inline-flex animate-marquee items-center hover:[animation-play-state:paused]">
            {displayItems.map((item, idx) => (
              <div
                key={`${item.cveId}-${idx}`}
                onClick={() => onSelectCve?.(item.cveId)}
                className="inline-flex items-center gap-2 mx-4 cursor-pointer group text-xs font-mono"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                <span className="text-rose-400 font-bold group-hover:underline">
                  {item.cveId}
                </span>
                <span className="text-slate-400">
                  [{item.vendor} {item.product}]
                </span>
                <span className="text-slate-300 truncate max-w-xs group-hover:text-white">
                  {item.title}
                </span>

                {item.isRansomware && (
                  <span className="px-1.5 py-0.2 text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800 rounded">
                    RANSOMWARE TARGET
                  </span>
                )}

                <span className="text-slate-600 ml-1">|</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
