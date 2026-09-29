"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { MENU } from "@/lib/menu";
import ProductCard from "@/components/ProductCard";

type Cart = Record<string, number>;
const priceOf = (id: string) => MENU.flatMap((c) => c.items).find((i) => i.id === id)?.price ?? 0;
const nameOf = (id: string) => MENU.flatMap((c) => c.items).find((i) => i.id === id)?.name ?? id;

export default function Home() {
  const [cart, setCart] = useState<Cart>({});
  const [q, setQ] = useState("");
  useEffect(() => {
    try { setCart(JSON.parse(localStorage.getItem("wfc-cart") ?? "{}")); } catch { /* mock only */ }
  }, []);
  useEffect(() => { localStorage.setItem("wfc-cart", JSON.stringify(cart)); }, [cart]);
  const add = (id: string) => setCart((c) => ({ ...c, [id]: (c[id] ?? 0) + 1 }));
  const total = Object.entries(cart).reduce((s, [id, q2]) => s + priceOf(id) * q2, 0);
  const count = Object.values(cart).reduce((s, v) => s + v, 0);
  const query = q.trim().toLowerCase();
  const shown = query ? MENU.map((c) => ({ ...c, items: c.items.filter((i) => i.name.toLowerCase().includes(query)) })).filter((c) => c.items.length > 0) : MENU;

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <main className="mx-auto max-w-4xl px-4 pb-24">
        <p className="mt-4 text-center text-[#ffb703] font-bold tracking-widest">CRISPY. JUICY. DELICIOUS.</p>
        <p className="text-center text-sm text-zinc-300">Bhadurpura, Hyderabad • Dine-in / Pickup / Delivery 3km • Mock-UI, no DB</p>
        <p className="mt-2 text-center"><Link href="/cart" className="inline-block rounded-full bg-black border border-[#ffb703] px-4 py-1 text-sm">Cart {count} • ₹{total} (mock) →</Link></p>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search menu… e.g. Zinger, Pizza, Waffle" className="mt-4 w-full rounded bg-zinc-900 px-3 py-2 text-sm" />
        {query && shown.length === 0 && <p className="mt-4 text-sm">No matches for “{q}” (mock).</p>}
        {shown.map((cat) => (
          <section key={cat.slug} className="mt-8">
            <h2 className="inline-block rounded bg-[#ffb703] px-3 py-1 font-extrabold text-black uppercase">{cat.name}</h2>
            <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
              {cat.items.map((it) => (
                <ProductCard key={it.id} id={it.id} name={it.name} price={it.price} count={cart[it.id] ?? 0} onAdd={() => add(it.id)} />
              ))}
            </div>
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
