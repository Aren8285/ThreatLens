// Thin API client — all backend calls go through here.
const BASE = import.meta.env.DEV ? '/api' : (window.__API_BASE__ || '/api');

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error */ }
  if (!res.ok) {
    throw new Error(data?.detail || data?.error || `HTTP ${res.status}`);
  }
  return data;
}

export async function health() {
  const res = await fetch(`${BASE}/health`);
  if (!res.ok) throw new Error(`Backend unreachable (HTTP ${res.status})`);
  return res.json();
}

export function analyze(payload) {
  return post('/analyze', payload);
}

export function ocrOnly(imageBase64) {
  return post('/ocr', { image_base64: imageBase64 });
}

/** Read a File (image) into a data-URI, enforcing ~8MB. */
export function fileToDataUri(file) {
  if (file.size > 8 * 1024 * 1024) {
    return Promise.reject(new Error('Image too large (max 8MB)'));
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result); // data-URI string
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}
