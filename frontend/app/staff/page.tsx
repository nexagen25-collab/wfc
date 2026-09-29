"use client";
import { useEffect, useState } from "react";
import MockGate from "@/components/MockGate";
type Order = { token: string; mode: string; pay: string; total: number; phone: string; at: string };
const FLOW = ["Placed", "Preparing", "Ready", "Completed"];
function StaffInner() {
  const [orders, setOrders] = useState<Order[]>([]);
  const [st, setSt] = useState<Record<string, string>>({});
  useEffect(() => {
    try { setOrders(JSON.parse(localStorage.getItem("wfc-orders") ?? "[]")); } catch {}
    try { setSt(JSON.parse(localStorage.getItem("wfc-status") ?? "{}")); } catch {}
  }, []);
  const adv = (t: string) => setSt((s) => {
    const cur = s[t] ?? "Placed"; const nx = FLOW[Math.min(FLOW.indexOf(cur) + 1, FLOW.length - 1)];
    const n = { ...s, [t]: nx }; localStorage.setItem("wfc-status", JSON.stringify(n)); return n;
  });
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <main className="mx-auto max-w-2xl px-4 py-6">
        <h1 className="text-xl font-black">Staff (mock, no login)</h1>
        {orders.length === 0 ? <p className="mt-2 text-sm">No orders yet.</p> : (
          <ul className="mt-3 divide-y divide-zinc-800 rounded border border-zinc-800 text-sm">
            {orders.map((o) => <li key={o.token} className="flex items-center justify-between px-3 py-2"><span>{o.token} • {o.mode} • ₹{o.total} • {st[o.token] ?? "Placed"}</span><button onClick={() => adv(o.token)} className="rounded bg-[#ffb703] px-2 py-1 font-bold text-black">Advance</button></li>)}
          </ul>
        )}
      </main>
    </div>
  );
}

export default function StaffPage() {
  return <MockGate area="Staff"><StaffInner /></MockGate>;
}
