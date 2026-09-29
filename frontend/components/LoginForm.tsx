"use client";
import Link from "next/link";
import { useState } from "react";

type Props = { role: "customer" | "admin" | "staff" };

export default function LoginForm({ role }: Props) {
  const [tab, setTab] = useState<"email" | "otp">("email");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [phone, setPhone] = useState("");
  const [otpSent, setOtpSent] = useState(false);
  const [otp, setOtp] = useState("");
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
  const phoneOk = /^[6-9]\d{9}$/.test(phone.trim());
  const otpOk = /^\d{4,6}$/.test(otp.trim());

  const submitEmail = (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailOk) return setErr("Enter a valid email address.");
    if (password.length < 6) return setErr("Password must be at least 6 characters.");
    setErr("");
    setDone(role === "customer" ? "Mock login OK → redirecting to Menu" : role === "admin" ? "Mock login OK → redirecting to Admin" : "Mock login OK → redirecting to Staff");
    setTimeout(() => { window.location.href = role === "customer" ? "/" : role === "admin" ? "/admin" : "/staff"; }, 1200);
  };

  const submitOtp = (e: React.FormEvent) => {
    e.preventDefault();
    if (!otpOk) return setErr("Enter the 4-6 digit OTP.");
    setErr("");
    setDone("Mock OTP accepted → redirecting");
    setTimeout(() => { window.location.href = role === "customer" ? "/" : role === "admin" ? "/admin" : "/staff"; }, 1200);
  };

  const input = "mt-1 w-full min-h-11 rounded-lg bg-zinc-900 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[#ffb703]";

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0a0a0a] px-4 text-white">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
        <p className="text-center text-2xl font-black">WFC</p>
        <p className="mt-1 text-center text-xs tracking-widest text-[#ffb703]">
          {role === "customer" ? "ORDER ONLINE" : role === "admin" ? "ADMIN PANEL" : "STAFF PANEL"}
        </p>

        <div className="mt-5 flex rounded-lg bg-zinc-900 p-1 text-sm">
          <button onClick={() => { setTab("email"); setErr(""); }} className={`flex-1 rounded-md py-2 ${tab === "email" ? "bg-[#c1121f] font-bold" : ""}`}>Email + Password</button>
          <button onClick={() => { setTab("otp"); setErr(""); }} className={`flex-1 rounded-md py-2 ${tab === "otp" ? "bg-[#c1121f] font-bold" : ""}`}>Phone OTP</button>
        </div>

        {tab === "email" ? (
          <form onSubmit={submitEmail} className="mt-4 space-y-3">
            <div><label className="text-xs text-zinc-400">Email</label>
              <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="email" placeholder="you@example.com" className={input} /></div>
            <div><label className="text-xs text-zinc-400">Password</label>
              <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" placeholder="Min 6 characters" className={input} /></div>
            {err && <p className="text-xs text-red-400">{err}</p>}
            <button className="min-h-11 w-full rounded-lg bg-[#ffb703] font-black text-black">Login</button>
          </form>
        ) : (
          <form onSubmit={submitOtp} className="mt-4 space-y-3">
            <div><label className="text-xs text-zinc-400">Phone (10 digits)</label>
              <input value={phone} onChange={(e) => setPhone(e.target.value)} inputMode="numeric" placeholder="98XXXXXXXX" className={input} />
              <button type="button" onClick={() => { if (!phoneOk) setErr("Enter a valid 10-digit Indian mobile number."); else { setErr(""); setOtpSent(true); } }} disabled={!otpSent} className="mt-2 min-h-11 w-full rounded-lg border border-[#ffb703] py-2 text-sm font-bold text-[#ffb703] disabled:opacity-50">
                {otpSent ? "OTP sent (mock) — resend" : "Send OTP"}
              </button>
            </div>
            {otpSent && <div><label className="text-xs text-zinc-400">OTP</label>
              <input value={otp} onChange={(e) => setOtp(e.target.value)} inputMode="numeric" placeholder="4-6 digits" className={input} /></div>}
            {err && <p className="text-xs text-red-400">{err}</p>}
            <button disabled={!otpSent} className="min-h-11 w-full rounded-lg bg-[#ffb703] font-black text-black disabled:opacity-40">Verify + Login</button>
          </form>
        )}

        {done && <p className="mt-3 rounded-lg bg-green-950 p-2 text-center text-xs text-green-300">{done}</p>}

        <p className="mt-5 text-center text-[10px] leading-4 text-zinc-500">
          MOCK LOGIN — accepts any valid-looking credentials. No database, no real session, no real OTP. Live auth (Railway DB + MSG91) is still pending.
        </p>
        <Link href="/" className="mt-2 block text-center text-xs underline text-zinc-400">Back to menu</Link>
      </div>
    </div>
  );
}
