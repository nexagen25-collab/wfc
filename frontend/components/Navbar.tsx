"use client";
import Link from "next/link";
export default function Navbar() {
  return (
    <nav className="sticky top-0 z-10 flex items-center justify-between bg-[#c1121f] px-4 py-3 font-black">
      <Link href="/">WFC <span className="text-[#ffb703]">WARSI</span></Link>
      <span className="flex gap-4 text-sm">
        <Link href="/">Menu</Link>
        <Link href="/cart">Cart</Link>
        <Link href="/checkout">Checkout</Link>
      </span>
    </nav>
  );
}
