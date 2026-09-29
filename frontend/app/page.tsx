"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { MENU } from "@/lib/menu";
import ProductCard from "@/components/ProductCard";

type Cart = Record<string, number>;
const all = MENU.flatMap((c) => c.items);
const priceOf = (id: string) => all.find((i) => i.id === id)?.price ?? 0;
const nameOf = (id: string) => all.find((i) => i.id === id)?.name ?? id;

export default function Home() {
  const [cart, setCart] = useState<Cart>({});
  const [q, setQ] = useState("");
  const [active, setActive] = useState(MENU[0].slug);
  const railRef = useRef<HTMLDivElement>(null);
  const secRefs = useRef<Record<string, HTMLElement | null>>({});

  useEffect(() => {
    try { setCart(JSON.parse(localStorage.getItem("wfc-cart") ?? "{}")); } catch { /* mock only */ }
  }, []);
  useEffect(() => { localStorage.setItem("wfc-cart", JSON.stringify(cart)); }, [cart]);

  const add = (id: string) => setCart((c) => ({ ...c, [id]: (c[id] ?? 0) + 1 }));
  const total = Object.entries(cart).reduce((s, [id, v]) => s + priceOf(id) * v, 0);
  const count = Object.values(cart).reduce((s, v) => s + v, 0);

  const query = q.trim().toLowerCase();
  const shown = query
    ? MENU.map((c) => ({ ...c, items: c.items.filter((i) => i.name.toLowerCase().includes(query)) })).filter((c) => c.items.length > 0)
    : MENU;

  const jump = (slug: string) => {
    setActive(slug);
    secRefs.current[slug]?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] pb-24 text-white">
      {/* HERO — Combos upsell, above the fold on all sizes */}
      <section className="relative overflow-hidden bg-gradient-to-br from-[#c1121f] via-[#8f0d17] to-black">
        <div className="mx-auto max-w-6xl px-4 py-8 sm:py-12">
          <p className="text-xs font-bold tracking-[0.3em] text-[#ffb703]">WARSI FRIED CHICKEN</p>
          <h1 className="mt-2 text-3xl font-black leading-tight sm:text-5xl">CRISPY. JUICY. <span className="text-[#ffb703]">DELICIOUS.</span></h1>
          <p className="mt-2 max-w-lg text-sm text-zinc-200 sm:text-base">Bhadurpura, Hyderabad • Dine-in, Pickup &amp; Delivery within 3km — free.</p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button onClick={() => jump("combos")} className="min-h-11 rounded-lg bg-[#ffb703] px-5 py-2 font-black text-black transition hover:brightness-95">See Combos</button>
            <button onClick={() => jump("burgers")} className="min-h-11 rounded-lg border border-white/40 px-5 py-2 font-bold transition hover:bg-white/10">Browse Burgers</button>
          </div>
        </div>
      </section>

      {/* SEARCH */}
      <div className="mx-auto max-w-6xl px-4 pt-5">
        <label htmlFor="menu-search" className="sr-only">Search menu</label>
        <input id="menu-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search menu… e.g. Zinger, Pizza, Waffle"
          className="min-h-11 w-full rounded-xl bg-zinc-900 px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-[#ffb703]" />
      </div>

      {/* STICKY CATEGORY RAIL */}
      {!query && (
        <div className="sticky top-[52px] z-20 mt-4 border-y border-zinc-800 bg-[#0a0a0a]/95 backdrop-blur">
          <div ref={railRef} className="mx-auto flex max-w-6xl gap-2 overflow-x-auto px-4 py-2 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
            {MENU.map((c) => (
              <button key={c.slug} onClick={() => jump(c.slug)}
                aria-current={active === c.slug}
                className={`min-h-9 shrink-0 whitespace-nowrap rounded-full px-4 py-1.5 text-sm font-bold transition ${active === c.slug ? "bg-[#ffb703] text-black" : "bg-zinc-900 text-zinc-200 hover:bg-zinc-800"}`}>
                {c.name}
              </button>
            ))}
          </div>
        </div>
      )}

      <main className="mx-auto max-w-6xl px-4 pt-4">
        {query && shown.length === 0 && (
          <div className="mt-6 rounded-xl border border-zinc-800 bg-zinc-950 p-8 text-center">
            <p className="font-bold">No matches for “{q}”</p>
            <button onClick={() => setQ("")} className="mt-3 min-h-11 rounded-lg bg-[#c1121f] px-4 py-2 text-sm font-bold">Clear search</button>
          </div>
        )}

        {shown.map((cat) => (
          <section key={cat.slug} ref={(el) => { secRefs.current[cat.slug] = el; }} className="mt-8 scroll-mt-32">
            <div className="flex items-baseline justify-between">
              <h2 className="inline-block rounded bg-[#ffb703] px-3 py-1 font-extrabold uppercase text-black">{cat.name}</h2>
              <span className="text-xs text-zinc-500">{cat.items.length} items</span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
              {cat.items.map((it) => (
                <ProductCard key={it.id} id={it.id} name={it.name} price={it.price} count={cart[it.id] ?? 0} onAdd={() => add(it.id)} />
              ))}
            </div>
          </section>
        ))}

        {count > 0 && (
          <div className="mt-10 rounded-xl border border-[#ffb703] p-4 text-sm">
            <p className="font-bold">Mock cart (localStorage only, Qty-only, no fees):</p>
            <ul className="mt-1 grid gap-1 sm:grid-cols-2">
              {Object.entries(cart).map(([id, v]) => <li key={id}>{nameOf(id)} × {v} = ₹{priceOf(id) * v}</li>)}
            </ul>
            <p className="mt-2 font-bold">Total = ₹{total} (sum×qty − discount, zero fees per D011)</p>
          </div>
        )}
      </main>

      {/* STICKY CART BAR */}
      {count > 0 && (
        <div className="fixed inset-x-0 bottom-0 z-30 border-t border-zinc-800 bg-black/95 backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-4 py-3">
            <div className="text-sm">
              <p className="font-bold">{count} item{count > 1 ? "s" : ""}</p>
              <p className="text-[#ffb703]">₹{total}</p>
            </div>
            <Link href="/cart" className="min-h-11 rounded-lg bg-[#c1121f] px-5 py-2 font-bold">View cart →</Link>
          </div>
        </div>
      )}
    </div>
  );
}
