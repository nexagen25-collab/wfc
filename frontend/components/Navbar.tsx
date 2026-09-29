"use client";
import Link from "next/link";
import { useState } from "react";
export default function Navbar() {
  const [logoOk, setLogoOk] = useState(true);
  return (
    <nav className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-2 bg-[#c1121f] px-3 py-2 font-black sm:px-4">
      <Link href="/" className="flex items-center gap-2 text-base sm:text-lg">
        {logoOk ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src="/logo.png" alt="WFC logo" onError={() => setLogoOk(false)} className="h-9 w-9 rounded-full object-cover" />
        ) : (
          <span className="flex h-9 w-9 items-center justify-center rounded-full bg-black text-xs text-[#ffb703]">WFC</span>
        )}
        <span>WFC</span>
      </Link>
      <span className="flex flex-wrap gap-2 text-xs sm:gap-4 sm:text-sm">
        <Link href="/">Menu</Link>
        <Link href="/cart">Cart</Link>
        <Link href="/checkout">Checkout</Link>
        <Link href="/orders">Orders</Link>
        <Link href="/login">Login</Link>
        <Link href="/register">Register</Link>
        <Link href="/staff">Staff</Link>
        <Link href="/admin">Admin</Link>
      </span>
    </nav>
  );
}
