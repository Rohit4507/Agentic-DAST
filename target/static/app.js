/*!
 * Partner portal bundle (synthetic fixture for the mock target).
 * Route strings only -- this file exists so the static harvest has something to read,
 * and so the zombie candidates (/api/v1, /api/old, /api/test) are discoverable.
 * /api/internal/... is deliberately absent: that is the shadow API.
 */
const API = "/api";

async function api(path, options) {
  const res = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options && options.headers) },
  });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

export const bookings = {
  list: () => api("/api/bookings"),
  get: (id) => api(`/api/booking/${id}`),
  ledger: (id) => api(`/api/ledger/${id}`),
  hold: (body) => api("/api/hold", { method: "POST", body: JSON.stringify(body) }),
  pay: (body) => api("/api/pay", { method: "POST", body: JSON.stringify(body) }),
  confirm: (body) => api("/api/confirm", { method: "POST", body: JSON.stringify(body) }),
  cancel: (body) => api("/api/cancel", { method: "POST", body: JSON.stringify(body) }),
  refund: (body) => api("/api/refund", { method: "POST", body: JSON.stringify(body) }),
  rebook: (body) => api("/api/rebook", { method: "POST", body: JSON.stringify(body) }),
};

// Legacy support panel. Kept "just in case" -- and never called by the current UI,
// which is exactly why these routes are zombie candidates.
export const legacy = {
  v1Booking: (id) => api(`/api/v1/booking/${id}`),
  agencySummary: (id) => api(`/api/old/agency/${id}/summary`),
  debug: () => api("/api/test/debug"),
};

export const health = () => api("/healthz");
