"use client";
import Link from "next/link";
import { useState } from "react";

export default function RegisterPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [agree, setAgree] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
  const phoneOk = /^[6-9]\d{9}$/.test(phone.trim());
  const strong = pw.length >= 8 && /[A-Za-z]/.test(pw) && /\d/.test(pw);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (name.trim().length < 2) return setErr("Enter your full name.");
    if (!emailOk) return setErr("Enter a valid email address.");
    if (!phoneOk) return setErr("Enter a valid 10-digit Indian mobile number.");
    if (!strong) return setErr("Password needs 8+ characters with at least one letter and one number.");
    if (pw !== pw2) return setErr("Passwords do not match.");
    if (!agree) return setErr("Please accept the terms to continue.");
    setErr("");
    setDone("Mock account created → redirecting to Menu");
    setTimeout(() => { window.location.href = "/"; }, 1200);
  };

  const input = "mt-1 w-full min-h-11 rounded-lg bg-zinc-900 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[#ffb703]";
  const label = "text-xs text-zinc-400";

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0a0a0a] px-4 py-8 text-white">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
        <p className="text-center text-2xl font-black">WFC</p>
        <p className="mt-1 text-center text-xs tracking-widest text-[#ffb703]">CREATE ACCOUNT</p>

        <form onSubmit={submit} className="mt-5 space-y-3">
          <div><label className={label} htmlFor="r-name">Full name</label>
            <input id="r-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" placeholder="Your name" className={input} /></div>
          <div><label className={label} htmlFor="r-email">Email</label>
            <input id="r-email" value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="email" placeholder="you@example.com" className={input} /></div>
          <div><label className={label} htmlFor="r-phone">Phone (10 digits)</label>
            <input id="r-phone" value={phone} onChange={(e) => setPhone(e.target.value)} inputMode="numeric" autoComplete="tel" placeholder="98XXXXXXXX" className={input} /></div>
          <div><label className={label} htmlFor="r-pw">Password</label>
            <input id="r-pw" value={pw} onChange={(e) => setPw(e.target.value)} type="password" autoComplete="new-password" placeholder="8+ chars, letters and numbers" className={input} />
            {pw.length > 0 && <p className={`mt-1 text-[11px] ${strong ? "text-green-400" : "text-zinc-500"}`}>{strong ? "Password strength: good" : "Too weak — add length, a letter and a number"}</p>}</div>
          <div><label className={label} htmlFor="r-pw2">Confirm password</label>
            <input id="r-pw2" value={pw2} onChange={(e) => setPw2(e.target.value)} type="password" autoComplete="new-password" placeholder="Repeat password" className={input} /></div>
          <label className="flex items-start gap-2 text-xs text-zinc-400">
            <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} className="mt-0.5" />
            I agree to the WFC terms and privacy policy.
          </label>
          {err && <p className="text-xs text-red-400">{err}</p>}
          {done && <p className="rounded-lg bg-green-950 p-2 text-center text-xs text-green-300">{done}</p>}
          <button className="min-h-11 w-full rounded-lg bg-[#ffb703] font-black text-black">Create account</button>
        </form>

        <p className="mt-5 text-[10px] leading-4 text-zinc-500">
          MOCK REGISTRATION — nothing is saved, no account is created, no email or SMS is sent. Real signup needs a database (Railway) and MSG91.
        </p>
        <p className="mt-2 text-center text-xs text-zinc-400">Already registered? <Link href="/login" className="underline text-[#ffb703]">Login</Link></p>
      </div>
    </div>
  );
}
