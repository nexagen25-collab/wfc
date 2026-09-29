"use client";
import { useEffect, useState } from "react";
type Order = { token: string; cart: Record<string, number>; mode: string; pay: string; phone: string; total: number; at: string };
export default function OrdersPage() {
  const [orders, setOrders] = useState<Order[]>([]);
  useEffect(() => { try { setOrders(JSON.parse(localStorage.getItem("wfc-orders") ?? "[]")); } catch {} }, []);
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <main className="mx-auto max-w-2xl px-4 py-6">
        <h1 className="text-xl font-black">My Orders (mock)</h1>
        {orders.length === 0 ? <p className="mt-2 text-sm">No orders yet. Place one via Checkout.</p> : (
          <ul className="mt-3 divide-y divide-zinc-800 rounded border border-zinc-800 text-sm">
            {orders.map((o) => <li key={o.token} className="px-3 py-2">{o.token} • {o.mode} • {o.pay} • ₹{o.total} • Placed mock • {new Date(o.at).toLocaleString()}</li>)}
          </ul>
        )}
      </main>
    </div>
  );
}
