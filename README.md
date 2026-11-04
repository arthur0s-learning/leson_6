# Atelier

Authentification HTML/CSS/JS servie par Node.js 24 ou plus récent. Les comptes sont enregistrés dans `db.json` par JSON Server. `npm start` lance le site sur le port 3000 et l'API JSON Server sur le port local 3001.

Générez le poivre secret et créez `.env` à la racine :

```sh
node -e "console.log('AUTH_PEPPER=' + require('node:crypto').randomBytes(32).toString('hex'))" > .env
npm start
```

Ouvrez ensuite `http://localhost:3000`. Le fichier `db.json` est créé automatiquement s'il n'existe pas. L'API JSON Server écoute uniquement sur `127.0.0.1` et n'est pas exposée au réseau.

Chaque compte contient `email`, `password_hash` et `password_salt` (ainsi qu'un identifiant et la date de création). Le mot de passe est dérivé avec scrypt à partir du mot de passe combiné au poivre serveur; le sel aléatoire propre à chaque compte est stocké séparément. Le poivre reste dans `.env` et n'est jamais enregistré dans `db.json`.

JSON Server est prévu pour le développement et les prototypes, pas pour exposer une base de comptes sur un réseau non fiable ou en production.