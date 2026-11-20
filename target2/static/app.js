// Orders console -- deliberately ordinary front-end code.
// Every route below is harvested by `python run.py inventory`, which is why the
// zombie route (/v2/legacy/orders/{id}) is visible here at all: it is still shipped
// in the bundle but no longer called by any page.

import { authHeaders } from "./session.js";

export const API = "/v2/orders";

export async function loadOrder(id) {
  const res = await fetch(`${API}/${id}`, { headers: authHeaders() });
  return res.json();
}

export async function loadStatement(id) {
  return fetch(`/v2/orders/${id}/statement`, { headers: authHeaders() });
}

export async function settle(id, value) {
  return fetch(`/v2/orders/${id}/settle`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ value }),
  });
}

export async function confirm(id) {
  return fetch(`/v2/orders/${id}/confirm`, { method: "POST", headers: authHeaders() });
}

export async function cancel(id) {
  return fetch(`/v2/orders/${id}/cancel`, { method: "POST", headers: authHeaders() });
}

export async function refund(id, value) {
  return fetch(`/v2/orders/${id}/refund`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ value }),
  });
}

export async function reprice(id, total) {
  return fetch(`/v2/orders/${id}/reprice`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ total }),
  });
}

// Retained for the 2024 agent console, still bundled, no caller left.
export async function legacyOrder(id) {
  return fetch(`/v2/legacy/orders/${id}`);
}
