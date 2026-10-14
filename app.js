async function showHome() {
  const response = await fetch('/api/me');
  if (!response.ok) {
    window.location.replace('/login.html');
    return;
  }

  const { user } = await response.json();
  const greeting = document.querySelector('#home-greeting');
  if (greeting) greeting.textContent = `Bienvenue, ${user.email}, dans votre espace.`;

  document.querySelector('#logout-button')?.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.replace('/login.html');
  });
}

function setupAuthForm() {
  const form = document.querySelector('#auth-form');
  if (!form) return;

  const emailInput = document.querySelector('#email');
  const passwordInput = document.querySelector('#password');
  const message = document.querySelector('#form-message');
  const submitButton = document.querySelector('#submit-button');
  const modeButtons = document.querySelectorAll('[data-mode]');
  let mode = 'login';

  function setMode(nextMode) {
    mode = nextMode;
    const registering = mode === 'register';
    passwordInput.autocomplete = registering ? 'new-password' : 'current-password';
    document.querySelector('#form-kicker').textContent = registering ? 'BIENVENUE PARMI NOUS' : 'RAVI DE VOUS REVOIR';
    document.querySelector('#form-title').textContent = registering ? 'Créer un compte' : 'Connexion';
    document.querySelector('#form-intro').textContent = registering
      ? 'Quelques informations et votre espace est prêt.'
      : 'Connectez-vous pour accéder à votre espace.';
    submitButton.innerHTML = registering
      ? 'Créer mon compte <span aria-hidden="true">↗</span>'
      : 'Se connecter <span aria-hidden="true">↗</span>';
    message.textContent = '';
    message.classList.remove('is-success');
    modeButtons.forEach(button => {
      const active = button.dataset.mode === mode;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }

  modeButtons.forEach(button => button.addEventListener('click', () => setMode(button.dataset.mode)));

  form.addEventListener('submit', async event => {
    event.preventDefault();
    message.textContent = '';
    message.classList.remove('is-success');

    if (!form.reportValidity()) return;

    const email = emailInput.value.trim().toLowerCase();
    submitButton.disabled = true;
    message.textContent = '';

    try {
      const response = await fetch(`/api/${mode === 'register' ? 'register' : 'login'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: passwordInput.value })
      });
      const result = await response.json();
      if (!response.ok) {
        message.textContent = result.error || 'Une erreur est survenue.';
        return;
      }

      window.location.href = '/index.html';
    } catch {
      message.textContent = 'Impossible de joindre le serveur. Réessayez.';
    } finally {
      submitButton.disabled = false;
    }
  });
}

if (document.body.dataset.page === 'home') showHome();
else setupAuthForm();