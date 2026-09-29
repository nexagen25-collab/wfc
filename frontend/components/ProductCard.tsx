"use client";
import { useState } from "react";
export default function ProductCard({ id, name, price, count, onAdd }: { id: string; name: string; price: number; count: number; onAdd: () => void }) {
  const [imgOk, setImgOk] = useState(true);
  return (
    <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
      <div className="relative aspect-[4/3] bg-gradient-to-br from-[#c1121f] to-[#5c0a0a]">
        {imgOk ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={`/menu/${id}.jpg`} alt={name} onError={() => setImgOk(false)} className="h-full w-full object-cover" loading="lazy" />
        ) : (
          <div className="flex h-full w-full items-center justify-center px-2 text-center text-xs font-black tracking-widest text-[#ffb703]">WFC • {name}</div>
        )}
      </div>
      <div className="p-3">
        <p className="truncate text-sm font-bold sm:text-base">{name}</p>
        <div className="mt-2 flex items-center justify-between">
          <span className="font-black">₹{price}</span>
          <button onClick={onAdd} className="min-h-11 rounded-lg bg-[#c1121f] px-4 py-2 text-sm font-bold">Add{count ? ` (${count})` : ""}</button>
        </div>
      </div>
    </div>
  );
}
