"use client";
export default function SkeletonCards({ n = 4 }: { n?: number }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5" aria-hidden="true">
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className="animate-pulse overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
          <div className="aspect-[4/3] bg-zinc-900" />
          <div className="space-y-2 p-3">
            <div className="h-3 w-3/4 rounded bg-zinc-800" />
            <div className="flex items-center justify-between">
              <div className="h-4 w-10 rounded bg-zinc-800" />
              <div className="h-9 w-16 rounded-lg bg-zinc-800" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
