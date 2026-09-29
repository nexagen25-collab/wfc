export type MenuItem = { id: string; name: string; price: number };
export type MenuCategory = { slug: string; name: string; items: MenuItem[] };

export const MENU: MenuCategory[] = [
  { slug: "burgers", name: "Burgers", items: [
    { id: "chicken-burger", name: "Chicken Burger", price: 100 },
    { id: "chicken-cheese-burger", name: "Chicken Cheese Burger", price: 120 },
    { id: "zinger-burger", name: "Zinger Burger", price: 120 },
    { id: "veg-burger", name: "Veg Burger", price: 80 },
    { id: "veg-cheese-burger", name: "Veg Cheese Burger", price: 90 },
  ]},
  { slug: "wraps", name: "Wraps", items: [
    { id: "chicken-wrap", name: "Chicken Wrap", price: 100 },
    { id: "chicken-zinger-wrap", name: "Chicken Zinger Wrap", price: 120 },
    { id: "chicken-nugget-wrap", name: "Chicken Nugget Wrap", price: 120 },
    { id: "veg-wrap", name: "Veg Wrap", price: 80 },
  ]},
  { slug: "pizzas", name: "Pizzas", items: [
    { id: "veg-pizza", name: "Veg Pizza", price: 100 },
    { id: "veg-cheese-pizza", name: "Veg Cheese Pizza", price: 130 },
    { id: "chicken-pizza", name: "Chicken Pizza", price: 180 },
    { id: "chicken-nuggets-pizza", name: "Chicken Nuggets Pizza", price: 220 },
    { id: "chicken-popcorn-pizza", name: "Chicken Popcorn Pizza", price: 220 },
  ]},
  { slug: "sandwich", name: "Sandwich", items: [
    { id: "chicken-sandwich", name: "Chicken Sandwich", price: 80 },
    { id: "chicken-nugget-sandwich", name: "Chicken Nugget Sandwich", price: 100 },
    { id: "veg-sandwich", name: "Veg Sandwich", price: 60 },
  ]},
  { slug: "fries", name: "Fries", items: [
    { id: "french-fries", name: "French Fries", price: 80 },
    { id: "peri-peri-fries", name: "Peri Peri Fries", price: 100 },
    { id: "cheesy-fries", name: "Cheesy Fries", price: 120 },
  ]},
  { slug: "brosted", name: "Brosted Chicken", items: [
    { id: "brosted-2", name: "Brosted Chicken 2 pcs", price: 140 },
    { id: "brosted-4", name: "Brosted Chicken 4 pcs", price: 260 },
    { id: "brosted-8", name: "Brosted Chicken 8 pcs", price: 520 },
  ]},
  { slug: "waffles", name: "Waffles", items: [
    { id: "biscuit-choc", name: "Biscuit Waffle Choc", price: 25 },
    { id: "biscuit-dark", name: "Biscuit Waffle Dark", price: 50 },
    { id: "biscuit-milky", name: "Biscuit Waffle Milky", price: 80 },
    { id: "sandwich-dark", name: "Sandwich Waffle Dark", price: 130 },
    { id: "sandwich-milky", name: "Sandwich Waffle Milky", price: 150 },
    { id: "sandwich-white", name: "Sandwich Waffle White", price: 159 },
    { id: "round-dark", name: "Round Waffle Dark", price: 260 },
    { id: "round-milky", name: "Round Waffle Milky", price: 300 },
    { id: "round-white", name: "Round Waffle White", price: 300 },
  ]},
  { slug: "combos", name: "Combos", items: [
    { id: "combo-burger", name: "Burger + Fries + Cold Drink", price: 149 },
    { id: "combo-wrap", name: "Wrap + Fries + Cold Drink", price: 149 },
    { id: "combo-pizza", name: "Pizza + 2 Cold Drinks", price: 259 },
    { id: "combo-brosted", name: "Brosted 4pcs + Fries + 2 Cold Drinks", price: 359 },
  ]},
];
