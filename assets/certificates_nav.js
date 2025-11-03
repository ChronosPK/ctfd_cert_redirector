(function () {
  function addUserLink() {
    const nav = document.querySelector('nav.navbar .navbar-nav');
    if (!nav) return;
    if (nav.querySelector('a[href="/certificates"]')) return;

    const li = document.createElement('li');
    li.className = 'nav-item';
    const a = document.createElement('a');
    a.className = 'nav-link';
    a.href = '/certificates';
    a.textContent = 'Certificates';
    li.appendChild(a);
    nav.appendChild(li);
  }

  function addAdminLink() {
    // admin header: add under the right-side navbar if present
    const adminNav = document.querySelector('nav.navbar .navbar-nav');
    if (!adminNav) return;
    if (adminNav.querySelector('a[href="/admin/certificates"]')) return;

    const li = document.createElement('li');
    li.className = 'nav-item';
    const a = document.createElement('a');
    a.className = 'nav-link';
    a.href = '/admin/certificates';
    a.textContent = 'Certificates';
    li.appendChild(a);
    adminNav.appendChild(li);
  }

  document.addEventListener('DOMContentLoaded', function () {
    addUserLink();
    addAdminLink();
  });
})();
