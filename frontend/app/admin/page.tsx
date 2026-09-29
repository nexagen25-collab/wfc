"use client";
import { useEffect, useState } from "react";
import { MENU } from "@/lib/menu";

type Order = { token: string; cart: Record<string, number>; mode: string; pay: string; phone: string; total: number; at: string };

export default function AdminPage() {
  const [orders, setOrders] = useState<Order[]>([]);
  const [off, setOff] = useState<Record<string, boolean>>({});
  useEffect(() => {
    try { setOrders(JSON.parse(localStorage.getItem("wfc-orders") ?? "[]")); } catch {}
    try { setOff(JSON.parse(localStorage.getItem("wfc-off") ?? "{}")); } catch {}
  }, []);
  const toggle = (id: string) => setOff((o) => { const n = { ...o, [id]: !o[id] }; localStorage.setItem("wfc-off", JSON.stringify(n)); return n; });
  const sales = orders.reduce((s, o) => s + o.total, 0);
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <main className="mx-auto max-w-4xl px-4 py-6">
        <h1 className="text-xl font-black">Admin (mock, no login yet)</h1>
        <p className="mt-1 text-sm text-zinc-300">Sales ₹{sales} • Orders {orders.length} • localStorage only</p>
        <h2 className="mt-6 font-bold text-[#ffb703]">ORDERS</h2>
        {orders.length === 0 ? <p className="text-sm">No mock orders yet. Place one via Checkout.</p> : (
          <ul className="mt-2 divide-y divide-zinc-800 rounded border border-zinc-800 text-sm">
            {orders.map((o) => <li key={o.token} className="px-3 py-2">{o.token} • {o.mode} • {o.pay} • ₹{o.total} • {o.phone}</li>)}
          </ul>
        )}
        <h2 className="mt-6 font-bold text-[#ffb703]">AVAILABILITY (mock toggle)</h2>
        {MENU.map((c) => (
          <div key={c.slug} className="mt-2"><p className="text-sm font-bold">{c.name}</p>
            <ul className="divide-y divide-zinc-800 rounded border border-zinc-800 text-sm">
              {c.items.map((it) => <li key={it.id} className="flex justify-between px-3 py-1"><span>{it.name} ₹{it.price} {off[it.id] ? "(OFF)" : ""}</span><button onClick={() => toggle(it.id)} className="rounded bg-[#c1121f] px-2">Toggle</button></li>)}
            </ul>
          </div>
        ))}
      </main>
    </div>
  );
}
