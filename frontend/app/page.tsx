"use client";
import { useEffect, useState } from "react";
import { MENU } from "@/lib/menu";

type Cart = Record<string, number>;
const priceOf = (id: string) => MENU.flatMap((c) => c.items).find((i) => i.id === id)?.price ?? 0;
const nameOf = (id: string) => MENU.flatMap((c) => c.items).find((i) => i.id === id)?.name ?? id;

export default function Home() {
  const [cart, setCart] = useState<Cart>({});
  useEffect(() => {
    try { setCart(JSON.parse(localStorage.getItem("wfc-cart") ?? "{}")); } catch { /* mock only */ }
  }, []);
  useEffect(() => { localStorage.setItem("wfc-cart", JSON.stringify(cart)); }, [cart]);
  const add = (id: string) => setCart((c) => ({ ...c, [id]: (c[id] ?? 0) + 1 }));
  const total = Object.entries(cart).reduce((s, [id, q]) => s + priceOf(id) * q, 0);
  const count = Object.values(cart).reduce((s, q) => s + q, 0);

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <header className="sticky top-0 z-10 flex items-center justify-between bg-[#c1121f] px-4 py-3">
        <div className="font-black text-xl tracking-tight">WFC <span className="text-[#ffb703]">WARSI FRIED CHICKEN</span></div>
        <div className="rounded-full bg-black px-4 py-1 text-sm">Cart {count} • ₹{total} (mock)</div>
      </header>
      <main className="mx-auto max-w-4xl px-4 pb-24">
        <p className="mt-4 text-center text-[#ffb703] font-bold tracking-widest">CRISPY. JUICY. DELICIOUS.</p>
        <p className="text-center text-sm text-zinc-300">Bhadurpura, Hyderabad • Dine-in / Pickup / Delivery 3km • Mock-UI, no DB</p>
        {MENU.map((cat) => (
          <section key={cat.slug} className="mt-8">
            <h2 className="inline-block rounded bg-[#ffb703] px-3 py-1 font-extrabold text-black uppercase">{cat.name}</h2>
            <ul className="mt-3 divide-y divide-zinc-800 rounded border border-zinc-800">
              {cat.items.map((it) => (
                <li key={it.id} className="flex items-center justify-between px-3 py-2">
                  <span>{it.name}</span>
                  <span className="flex items-center gap-3">
                    <span className="font-bold">₹{it.price}</span>
                    <button onClick={() => add(it.id)} className="rounded bg-[#c1121f] px-3 py-1 text-sm font-bold">Add {cart[it.id] ? `(${cart[it.id]})` : ""}</button>
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ))}
        {count > 0 && (
          <div className="mt-8 rounded border border-[#ffb703] p-3 text-sm">
            <p className="font-bold">Mock cart (localStorage only, Qty-only, no fees):</p>
            <ul>{Object.entries(cart).map(([id, q]) => <li key={id}>{nameOf(id)} × {q} = ₹{priceOf(id) * q}</li>)}</ul>
            <p className="mt-2 font-bold">Total = ₹{total} (sum×qty − discount, zero fees per D011)</p>
          </div>
        )}
      </main>
    </div>
  );
}
