"use client";
import { useEffect, useState } from "react";
import { MENU } from "@/lib/menu";

export default function ProductView({ id }: { id: string }) {
  const [cart, setCart] = useState<Record<string, number>>({});
  const [qty, setQty] = useState(1);
  const [imgOk, setImgOk] = useState(true);
  useEffect(() => { try { setCart(JSON.parse(localStorage.getItem("wfc-cart") ?? "{}")); } catch {} }, []);
  useEffect(() => { localStorage.setItem("wfc-cart", JSON.stringify(cart)); }, [cart]);

  const found = MENU.flatMap((c) => ({ cat: c.name, items: c.items })).find((g) => g.items.some((i) => i.id === id));
  const item = found?.items.find((i) => i.id === id);
  if (!item) return <div className="min-h-screen bg-[#0a0a0a] p-6 text-white">Item not found. <a href="/" className="underline text-[#ffb703]">Back to menu</a></div>;

  const inCart = cart[id] ?? 0;
  const addQty = (q: number) => setCart((c) => ({ ...c, [id]: (c[id] ?? 0) + q }));

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <div className="mx-auto max-w-3xl px-4 py-6">
        <a href="/" className="text-sm underline text-zinc-400">← {found?.cat}</a>
        <div className="mt-3 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
          <div className="relative aspect-[16/9] bg-gradient-to-br from-[#c1121f] to-[#5c0a0a]">
            {imgOk ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={`/menu/${id}.jpg`} alt={item.name} onError={() => setImgOk(false)} className="h-full w-full object-cover" />
            ) : (
              <div className="flex h-full w-full items-center justify-center px-4 text-center text-sm font-black tracking-widest text-[#ffb703]">WFC • {item.name}</div>
            )}
          </div>
          <div className="p-4">
            <p className="text-xs uppercase tracking-widest text-zinc-400">{found?.cat}</p>
            <h1 className="mt-1 text-xl font-black sm:text-2xl">{item.name}</h1>
            <p className="mt-2 text-2xl font-black text-[#ffb703]">₹{item.price}</p>
            <p className="mt-1 text-xs text-zinc-500">Qty-only item. No variants or add-ons (D009).</p>
            {inCart > 0 && <p className="mt-2 text-sm text-green-400">{inCart} already in cart → <a href="/cart" className="underline">view cart</a></p>}
            <div className="mt-4 flex flex-col gap-4 sm:flex-row sm:items-center">
              <div className="flex items-center gap-3">
                <button onClick={() => setQty((q) => Math.max(1, q - 1))} className="min-h-11 min-w-11 rounded-lg bg-zinc-800 px-3 py-2 text-lg">−</button>
                <span className="w-8 text-center text-lg font-bold">{qty}</span>
                <button onClick={() => setQty((q) => Math.min(20, q + 1))} className="min-h-11 min-w-11 rounded-lg bg-zinc-800 px-3 py-2 text-lg">+</button>
              </div>
              <button onClick={() => addQty(qty)} className="min-h-11 flex-1 rounded-lg bg-[#c1121f] px-4 py-2 font-bold">Add {qty} to cart · ₹{item.price * qty}</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
