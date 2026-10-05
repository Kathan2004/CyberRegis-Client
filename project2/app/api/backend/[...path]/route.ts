/**
 * Server-side proxy to the CyberRegis Flask API.
 *
 * The browser calls /api/backend/<path>; this handler forwards the request to
 * CYBERREGIS_BACKEND_URL/<path> and attaches CYBERREGIS_API_TOKEN. The token is
 * only read on the server, so it never ships in the client bundle.
 */
import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const BACKEND_URL = (process.env.CYBERREGIS_BACKEND_URL || "http://127.0.0.1:5000").replace(/\/+$/, "");
const API_TOKEN = process.env.CYBERREGIS_API_TOKEN || "";

// Only the Flask API namespace may be reached through the proxy.
const ALLOWED_PREFIX = "api/";
const FORWARDED_REQUEST_HEADERS = ["content-type", "accept"];

async function forward(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const target = path.map(encodeURIComponent).join("/");
  if (!target.startsWith(ALLOWED_PREFIX) || path.some((p) => p === ".." || p === ".")) {
    return NextResponse.json({ status: "error", error: { message: "Not found", code: "ERR_404" } }, { status: 404 });
  }

  const headers = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = req.headers.get(name);
    if (value) headers.set(name, value);
  }
  if (API_TOKEN) headers.set("Authorization", `Bearer ${API_TOKEN}`);

  const hasBody = !["GET", "HEAD"].includes(req.method);
  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND_URL}/${target}${req.nextUrl.search}`, {
      method: req.method,
      headers,
      body: hasBody ? await req.arrayBuffer() : undefined,
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { status: "error", error: { message: "Backend unreachable", code: "ERR_502" } },
      { status: 502 },
    );
  }

  const out = new Headers();
  const contentType = upstream.headers.get("content-type");
  if (contentType) out.set("content-type", contentType);
  out.set("cache-control", "no-store");
  return new NextResponse(upstream.body, { status: upstream.status, headers: out });
}

export { forward as GET, forward as POST, forward as PUT, forward as DELETE };
