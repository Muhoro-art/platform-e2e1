function authHeader() {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function requireAuth() {
  const response = await fetch('/auth/me', { headers: { ...authHeader() } });
  if (!response.ok) {
    window.location.href = '/signin.html';
    return null;
  }
  const data = await response.json();
  return data.user;
}

window.platformAuth = { authHeader, requireAuth };
