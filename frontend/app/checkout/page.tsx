"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { MENU } from "@/lib/menu";
import { discountFor } from "@/lib/coupons";

type Cart = Record<string, number>;
const all = MENU.flatMap((c) => c.items);
const priceOf = (id: string) => all.find((i) => i.id === id)?.price ?? 0;

export default function CheckoutPage() {
  const [cart, setCart] = useState<Cart>({});
  const [mode, setMode] = useState<"dinein" | "pickup" | "delivery">("pickup");
  const [pay, setPay] = useState<"COD" | "Razorpay">("COD");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [token, setToken] = useState("");
  useEffect(() => { try { setCart(JSON.parse(localStorage.getItem("wfc-cart") ?? "{}")); } catch {} }, []);
  const subtotal = Object.entries(cart).reduce((s, [id, q]) => s + priceOf(id) * q, 0);
  const discount = discountFor(code, subtotal);
  const total = subtotal - discount;
  const place = () => {
    const t = "WFC" + Math.floor(1000 + Math.random() * 9000);
    setToken(t);
    try {
      const orders = JSON.parse(localStorage.getItem("wfc-orders") ?? "[]");
      orders.push({ token: t, cart, mode, pay, phone, total, at: new Date().toISOString() });
      localStorage.setItem("wfc-orders", JSON.stringify(orders));
      localStorage.setItem("wfc-cart", "{}"); setCart({});
    } catch {}
  };
  if (token) return <div className="min-h-screen bg-[#0a0a0a] p-6 text-white"><p className="text-[#ffb703] font-black text-2xl">Order placed (mock) — Token {token}</p><p className="mt-2 text-sm">Mode {mode} • Pay {pay} • Total ₹{total} • No real charge, no SMS.</p><Link href="/" className="mt-4 inline-block underline">Back home</Link></div>;
  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <header className="flex items-center justify-between bg-[#c1121f] px-4 py-3 font-black"><Link href="/cart">← Cart</Link><span>Mock Checkout</span></header>
      <main className="mx-auto max-w-2xl space-y-4 px-4 py-6">
        <div><p className="font-bold">Service mode</p><div className="flex flex-col gap-2 text-sm sm:flex-row sm:gap-0">{(["dinein","pickup","delivery"] as const).map((m) => <label key={m} className="mr-3 flex min-h-11 items-center gap-1"><input type="radio" checked={mode===m} onChange={()=>setMode(m)} /> {m}{m==="delivery" ? " (free 3km mock)" : ""}</label>)}</div></div>
        <div><p className="font-bold">Payment</p><div className="flex flex-col gap-2 text-sm sm:flex-row sm:gap-0">{(["COD","Razorpay"] as const).map((p) => <label key={p} className="mr-3 flex min-h-11 items-center gap-1"><input type="radio" checked={pay===p} onChange={()=>setPay(p)} /> {p}{p==="Razorpay" ? " (mock, no charge)" : " (pay at counter)"}</label>)}</div></div>
        <div><p className="font-bold">Phone (mock, no OTP yet)</p><input value={phone} onChange={(e)=>setPhone(e.target.value)} placeholder="98XXXXXXXX" className="mt-1 w-full rounded bg-zinc-900 px-3 py-2" /></div>
        <div><p className="font-bold">Coupon (mock: WFC10 = 10% off min ₹199)</p><input value={code} onChange={(e)=>setCode(e.target.value)} placeholder="WFC10" className="mt-1 w-full rounded bg-zinc-900 px-3 py-2" />{code ? <p className="text-sm text-[#ffb703]">{discount > 0 ? `Applied −₹${discount}` : "Invalid / below min"}</p> : null}</div>
        <p className="font-bold">Subtotal ₹{subtotal} − Discount ₹{discount} = Total ₹{total}</p>
        <button onClick={place} disabled={total===0} className="min-h-11 w-full rounded bg-[#ffb703] py-3 font-bold text-black disabled:opacity-40">Place mock order</button>
      </main>
    </div>
  );
}
