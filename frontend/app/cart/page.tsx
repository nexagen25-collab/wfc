"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { MENU } from "@/lib/menu";

type Cart = Record<string, number>;
const all = MENU.flatMap((c) => c.items);
const priceOf = (id: string) => all.find((i) => i.id === id)?.price ?? 0;
const nameOf = (id: string) => all.find((i) => i.id === id)?.name ?? id;

export default function CartPage() {
  const [cart, setCart] = useState<Cart>({});
  useEffect(() => { try { setCart(JSON.parse(localStorage.getItem("wfc-cart") ?? "{}")); } catch {} }, []);
  useEffect(() => { localStorage.setItem("wfc-cart", JSON.stringify(cart)); }, [cart]);
  const total = Object.entries(cart).reduce((s, [id, q]) => s + priceOf(id) * q, 0);
  const setQty = (id: string, q: number) => setCart((c) => { const n = { ...c }; if (q <= 0) delete n[id]; else n[id] = q; return n; });
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <header className="flex items-center justify-between bg-[#c1121f] px-4 py-3 font-black"><Link href="/">WFC</Link><span>Mock Cart</span></header>
      <main className="mx-auto max-w-2xl px-4 py-6">
        {Object.keys(cart).length === 0 ? <p>Cart empty (mock). <Link href="/" className="underline text-[#ffb703]">Browse menu</Link></p> : (
          <>
            <ul className="divide-y divide-zinc-800 rounded border border-zinc-800">
              {Object.entries(cart).map(([id, q]) => (
                <li key={id} className="flex items-center justify-between px-3 py-2">
                  <span>{nameOf(id)} — ₹{priceOf(id)}</span>
                  <span className="flex items-center gap-2">
                    <button onClick={() => setQty(id, q - 1)} className="rounded bg-zinc-800 px-2">-</button>
                    <span>{q}</span>
                    <button onClick={() => setQty(id, q + 1)} className="rounded bg-zinc-800 px-2">+</button>
                    <span className="w-16 text-right font-bold">₹{priceOf(id) * q}</span>
                  </span>
                </li>
              ))}
            </ul>
            <p className="mt-4 text-right font-bold">Total ₹{total} (no fees)</p>
            <Link href="/checkout" className="mt-4 block rounded bg-[#ffb703] px-4 py-2 text-center font-bold text-black">Go to Checkout (mock)</Link>
          </>
        )}
      </main>
    </div>
  );
}
