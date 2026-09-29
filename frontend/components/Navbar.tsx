"use client";
import Link from "next/link";
export default function Navbar() {
  return (
    <nav className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-2 bg-[#c1121f] px-3 py-3 font-black sm:px-4">
      <Link href="/" className="text-base sm:text-lg">WFC <span className="text-[#ffb703]">WARSI</span></Link>
      <span className="flex flex-wrap gap-2 text-xs sm:gap-4 sm:text-sm">
        <Link href="/">Menu</Link>
        <Link href="/cart">Cart</Link>
        <Link href="/checkout">Checkout</Link>
        <Link href="/orders">Orders</Link>
        <Link href="/staff">Staff</Link>
        <Link href="/admin">Admin</Link>
      </span>
    </nav>
  );
}
