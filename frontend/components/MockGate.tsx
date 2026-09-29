import type { ReactNode } from "react";

/**
 * Blocks the mock-only screens in production builds.
 *
 * Why this exists: /admin and /staff accept any credentials, so if a mock build
 * were ever deployed publicly it would hand full control to any visitor. This
 * gate makes the mock fail CLOSED by default. It can only be forced on with an
 * explicit NEXT_PUBLIC_ALLOW_MOCK=true, so "I forgot" cannot expose the admin.
 */
const MOCK_BLOCKED =
  process.env.NODE_ENV === "production" && process.env.NEXT_PUBLIC_ALLOW_MOCK !== "true";

export default function MockGate({ area, children }: { area: string; children: ReactNode }) {
  if (MOCK_BLOCKED) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#0a0a0a] px-4 text-white">
        <div className="w-full max-w-md rounded-2xl border border-red-900 bg-zinc-950 p-6 text-center">
          <p className="text-lg font-black text-red-400">{area} is disabled</p>
          <p className="mt-2 text-sm text-zinc-400">
            This screen is a mock that accepts any credentials. It is blocked in production builds
            because it would give away {area.toLowerCase()} control to anyone.
          </p>
          <p className="mt-3 text-xs text-zinc-500">
            Real {area.toLowerCase()} access needs database-backed authentication, which is not
            built yet. This is a security stop, not a bug.
          </p>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}
