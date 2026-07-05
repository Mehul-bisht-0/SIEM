const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function request(path) {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

export function getLogs() {
  return request("/logs?limit=80");
}

export function getAlerts() {
  return request("/alerts?limit=30");
}

export function getAttackStats() {
  return request("/stats/attack-types");
}
