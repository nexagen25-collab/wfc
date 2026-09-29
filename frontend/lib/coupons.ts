export type Coupon = { code: string; kind: "percent"; value: number; minOrder: number };
export const COUPONS: Coupon[] = [
  { code: "WFC10", kind: "percent", value: 10, minOrder: 199 },
];
export function discountFor(code: string, subtotal: number): number {
  const c = COUPONS.find((x) => x.code === code.trim().toUpperCase());
  if (!c) return 0;
  if (subtotal < c.minOrder) return 0;
  return Math.floor((subtotal * c.value) / 100);
}
