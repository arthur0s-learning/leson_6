# Atelier

Authentification HTML/CSS/JS servie par Node.js 24 ou plus récent. SQLite est fourni par Node.js, aucune dépendance supplémentaire n'est requise.

Générez le poivre secret et créez `.env` à la racine :

```sh
node -e "console.log('AUTH_PEPPER=' + require('node:crypto').randomBytes(32).toString('hex'))" > .env
npm start
```

Ouvrez ensuite `http://localhost:3000`. La base est créée dans `data/users.sqlite`.

La table `users` contient `email`, `password_hash` et `password_salt` (ainsi qu'un identifiant et la date de création). Le mot de passe est dérivé avec scrypt à partir du mot de passe combiné au poivre serveur; le sel aléatoire propre à chaque compte est stocké séparément. Le poivre reste dans `.env` et n'est jamais enregistré en base.