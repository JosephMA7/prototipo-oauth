// Cerrar sesión
function logout() {
  localStorage.removeItem('token');
  sessionStorage.clear();
  location.href = '/static/index.html';
}

window.logout = logout;
