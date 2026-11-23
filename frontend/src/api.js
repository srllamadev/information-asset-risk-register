export async function request(path, token, options = {}) {
  const res = await fetch('/api/v1' + path, { ...options, headers: {'Content-Type':'application/json', ...(token ? {Authorization:`Bearer ${token}`} : {}), ...options.headers} });
  if (!res.ok) {
    if (res.status === 401 && token) window.dispatchEvent(new Event('sakura:session-expired'));
    let data; try { data = await res.json(); } catch { data = {}; }
    const detail = typeof data.detail === 'string' ? data.detail : Array.isArray(data.detail) ? data.detail.map(item => (item.msg || '').replace(/^Value error, /, '')).filter(Boolean).join('; ') : '';
    throw new Error(detail || 'No fue posible completar la operación.');
  }
  return res.status === 204 ? null : res.json();
}
