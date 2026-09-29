"use client";
import Link from "next/link";
import { useEffect, useState } from "react";

type Address = { id: string; label: string; line: string; area: string; isDefault: boolean };
type Profile = { name: string; email: string; phone: string };

const emptyForm = { label: "Home", line: "", area: "" };
const input = "mt-1 w-full min-h-11 rounded-lg bg-zinc-900 px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[#ffb703]";
const label = "text-xs text-zinc-400";
const card = "rounded-xl border border-zinc-800 bg-zinc-950 p-4";

export default function ProfilePage() {
  const [tab, setTab] = useState<"profile" | "addresses">("profile");
  const [profile, setProfile] = useState<Profile>({ name: "", email: "", phone: "" });
  const [list, setList] = useState<Address[]>([]);
  const [form, setForm] = useState(emptyForm);
  const [editing, setEditing] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState("");
  const [orders, setOrders] = useState<{ token: string; total: number }[]>([]);

  useEffect(() => {
    try {
      const p = JSON.parse(localStorage.getItem("wfc-profile") ?? "null");
      if (p && typeof p === "object" && typeof p.name === "string") setProfile(p as Profile);
    } catch { /* mock */ }
    try { setList(JSON.parse(localStorage.getItem("wfc-addresses") ?? "[]")); } catch { /* mock */ }
    try { setOrders(JSON.parse(localStorage.getItem("wfc-orders") ?? "[]")); } catch { /* mock */ }
  }, []);

  const persist = (p: Profile, l: Address[]) => {
    localStorage.setItem("wfc-profile", JSON.stringify(p));
    localStorage.setItem("wfc-addresses", JSON.stringify(l));
  };

  const saveProfile = (e: React.FormEvent) => {
    e.preventDefault();
    if (profile.name.trim().length < 2) return setErr("Enter your full name.");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(profile.email.trim())) return setErr("Enter a valid email address.");
    if (!/^[6-9]\d{9}$/.test(profile.phone.trim())) return setErr("Enter a valid 10-digit Indian mobile number.");
    setErr(""); setSaved("Profile saved (mock — stored in this browser only)");
    persist(profile, list);
  };

  const validateAddr = () => {
    if (form.label.trim().length < 2) return "Give this address a label (Home, Office…).";
    if (form.line.trim().length < 5) return "Enter the full address line.";
    if (form.area.trim().length < 2) return "Enter your area or village.";
    return "";
  };

  const saveAddress = (e: React.FormEvent) => {
    e.preventDefault();
    const v = validateAddr();
    if (v) return setErr(v);
    setErr("");
    if (editing) {
      const next = list.map((a) => (a.id === editing ? { ...a, label: form.label.trim(), line: form.line.trim(), area: form.area.trim() } : a));
      setList(next); persist(profile, next);
    } else {
      const next = [...list, { id: `addr-${Date.now()}`, label: form.label.trim(), line: form.line.trim(), area: form.area.trim(), isDefault: list.length === 0 }];
      setList(next); persist(profile, next);
    }
    setForm(emptyForm); setEditing(null); setSaved("Address saved (mock)");
  };

  const remove = (id: string) => { const next = list.filter((a) => a.id !== id); setList(next); persist(profile, next); setSaved("Address removed (mock)"); };

  const makeDefault = (id: string) => { const next = list.map((a) => ({ ...a, isDefault: a.id === id })); setList(next); persist(profile, next); };

  const startEdit = (a: Address) => { setEditing(a.id); setForm({ label: a.label, line: a.line, area: a.area }); setErr(""); };

  const totalSpent = orders.reduce((s, o) => s + o.total, 0);

  return (
    <div className="min-h-screen bg-[#0a0a0a] pb-16 text-white">
      <div className="mx-auto max-w-3xl px-4 py-6">
        <h1 className="text-2xl font-black">My Account</h1>
        <p className="mt-1 text-xs text-zinc-500">Mock profile — saved in this browser only. No server, no real account.</p>

        <div className="mt-4 flex rounded-lg bg-zinc-900 p-1 text-sm">
          <button onClick={() => setTab("profile")} className={`flex-1 rounded-md py-2 ${tab === "profile" ? "bg-[#c1121f] font-bold" : ""}`}>Profile</button>
          <button onClick={() => setTab("addresses")} className={`flex-1 rounded-md py-2 ${tab === "addresses" ? "bg-[#c1121f] font-bold" : ""}`}>Addresses ({list.length})</button>
        </div>

        {saved && <p className="mt-3 rounded-lg bg-green-950 p-2 text-center text-xs text-green-300">{saved}</p>}
        {err && <p className="mt-3 rounded-lg bg-red-950 p-2 text-center text-xs text-red-300">{err}</p>}

        {tab === "profile" ? (
          <form onSubmit={saveProfile} className="mt-4 space-y-3">
            <div className={card}>
              <div><label className={label} htmlFor="p-name">Full name</label>
                <input id="p-name" value={profile.name} onChange={(e) => setProfile({ ...profile, name: e.target.value })} className={input} /></div>
              <div className="mt-3"><label className={label} htmlFor="p-email">Email</label>
                <input id="p-email" value={profile.email} onChange={(e) => setProfile({ ...profile, email: e.target.value })} type="email" className={input} /></div>
              <div className="mt-3"><label className={label} htmlFor="p-phone">Phone</label>
                <input id="p-phone" value={profile.phone} onChange={(e) => setProfile({ ...profile, phone: e.target.value })} inputMode="numeric" className={input} /></div>
              <button className="mt-4 min-h-11 w-full rounded-lg bg-[#ffb703] font-black text-black">Save profile</button>
            </div>
            <div className={`${card} grid grid-cols-2 gap-3 text-center`}>
              <div><p className="text-2xl font-black text-[#ffb703]">{orders.length}</p><p className="text-xs text-zinc-400">Orders</p></div>
              <div><p className="text-2xl font-black text-[#ffb703]">₹{totalSpent}</p><p className="text-xs text-zinc-400">Total spent</p></div>
            </div>
            <p className="text-center text-xs text-zinc-500">Mock logout — sessions are not real yet. <Link href="/login" className="underline text-[#ffb703]">Login page</Link></p>
          </form>
        ) : (
          <div className="mt-4 space-y-3">
            <form onSubmit={saveAddress} className={card}>
              <p className="font-bold">{editing ? "Edit address" : "Add a delivery address"}</p>
              <div className="mt-3"><label className={label} htmlFor="a-label">Label</label>
                <input id="a-label" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="Home / Office" className={input} /></div>
              <div className="mt-3"><label className={label} htmlFor="a-line">Address line</label>
                <input id="a-line" value={form.line} onChange={(e) => setForm({ ...form, line: e.target.value })} placeholder="House / street / landmark" className={input} /></div>
              <div className="mt-3"><label className={label} htmlFor="a-area">Area</label>
                <input id="a-area" value={form.area} onChange={(e) => setForm({ ...form, area: e.target.value })} placeholder="Bhadurpura" className={input} /></div>
              <div className="mt-4 flex gap-2">
                <button className="min-h-11 flex-1 rounded-lg bg-[#ffb703] font-black text-black">{editing ? "Update address" : "Add address"}</button>
                {editing && <button type="button" onClick={() => { setEditing(null); setForm(emptyForm); setErr(""); }} className="min-h-11 rounded-lg border border-zinc-700 px-4 text-sm">Cancel</button>}
              </div>
              <p className="mt-2 text-[11px] text-zinc-500">WFC delivers within 3km of the Bhadurpura outlet (D014). No map pin or 3km check in this mock — that needs a maps provider you have not chosen yet.</p>
            </form>

            {list.length === 0 ? <p className="text-sm text-zinc-400">No saved addresses yet.</p> : list.map((a) => (
              <div key={a.id} className={card}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-bold">{a.label}{a.isDefault && <span className="ml-2 rounded bg-[#ffb703] px-1.5 py-0.5 text-[10px] font-black text-black">DEFAULT</span>}</p>
                    <p className="mt-1 text-sm text-zinc-300">{a.line}</p>
                    <p className="text-sm text-zinc-500">{a.area}</p>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {!a.isDefault && <button onClick={() => makeDefault(a.id)} className="min-h-9 rounded border border-zinc-700 px-3">Make default</button>}
                  <button onClick={() => startEdit(a)} className="min-h-9 rounded border border-zinc-700 px-3">Edit</button>
                  <button onClick={() => remove(a.id)} className="min-h-9 rounded border border-red-900 px-3 text-red-400">Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
