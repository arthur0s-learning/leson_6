async function showHome() {
  const response = await fetch('/api/me');
  if (!response.ok) {
    window.location.replace('/login.html');
    return;
  }

  const { user } = await response.json();
  const greeting = document.querySelector('#home-greeting');
  if (greeting) greeting.textContent = `Bienvenue, ${user.email}, dans votre espace.`;

  setupArticles();

  document.querySelector('#logout-button')?.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.replace('/login.html');
  });
}

async function setupArticles() {
  const list = document.querySelector('#article-list');
  const status = document.querySelector('#articles-message');
  const count = document.querySelector('#article-count');
  const form = document.querySelector('#article-form');
  const titleInput = document.querySelector('#article-title');
  const contentInput = document.querySelector('#article-content');
  const formMessage = document.querySelector('#article-form-message');
  const saveButton = document.querySelector('#save-article');
  const showFormButton = document.querySelector('#show-article-form');

  function setFormVisible(visible) {
    form.hidden = !visible;
    showFormButton.hidden = visible;
    if (visible) titleInput.focus();
  }

  function renderArticles(articles) {
    list.replaceChildren();
    count.textContent = String(articles.length).padStart(2, '0');
    status.hidden = articles.length > 0;
    status.textContent = articles.length ? '' : 'Aucun article pour le moment. Ajoutez votre première idée.';

    articles.forEach(article => {
      const card = document.createElement('article');
      card.className = 'article-card';

      const header = document.createElement('div');
      header.className = 'article-card-meta';
      const date = document.createElement('time');
      date.className = 'article-date';
      if (article.created_at) {
        const parsedDate = new Date(article.created_at);
        if (!Number.isNaN(parsedDate.getTime())) {
          date.dateTime = parsedDate.toISOString();
          date.textContent = new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium' }).format(parsedDate);
        }
      }
      const label = document.createElement('span');
      label.className = 'article-label';
      label.textContent = 'ARTICLE';
      header.append(date, label);

      const heading = document.createElement('h3');
      heading.textContent = article.title;
      const content = document.createElement('p');
      content.className = 'article-card-content';
      content.textContent = article.content;
      card.append(header, heading, content);
      list.append(card);
    });
  }

  async function loadArticles() {
    status.hidden = false;
    status.textContent = 'Chargement des articles…';
    try {
      const response = await fetch('/api/articles');
      if (response.status === 401) {
        window.location.replace('/login.html');
        return;
      }
      const articles = await response.json();
      if (!response.ok) throw new Error(articles.error || 'Impossible de charger les articles.');
      renderArticles(articles);
    } catch (error) {
      status.hidden = false;
      status.textContent = error.message || 'Impossible de charger les articles.';
    }
  }

  showFormButton.addEventListener('click', () => setFormVisible(true));
  document.querySelector('#hide-article-form').addEventListener('click', () => setFormVisible(false));
  document.querySelector('#cancel-article').addEventListener('click', () => {
    form.reset();
    formMessage.textContent = '';
    setFormVisible(false);
  });

  form.addEventListener('submit', async event => {
    event.preventDefault();
    formMessage.textContent = '';
    saveButton.disabled = true;
    try {
      const response = await fetch('/api/articles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: titleInput.value, content: contentInput.value })
      });
      const result = await response.json();
      if (!response.ok) {
        formMessage.textContent = result.error || 'Impossible de publier cet article.';
        return;
      }
      form.reset();
      setFormVisible(false);
      await loadArticles();
    } catch {
      formMessage.textContent = 'Impossible de joindre le serveur. Réessayez.';
    } finally {
      saveButton.disabled = false;
    }
  });

  await loadArticles();
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