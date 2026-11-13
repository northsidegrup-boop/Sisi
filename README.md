# NorthSide Community — web inicial

Sitio full-stack para desplegar en **Cloudflare Workers + D1**.

## Incluye
- Registro e inicio de sesión con contraseña cifrada mediante PBKDF2.
- Miembros dinámicos desde la base de datos.
- Foro: publicar temas y responder.
- Ranking editable de puntos y lista de destacados NorthSide.
- Panel de administración para gestionar miembros, puntos y destacados.
- Sección de colaboración **SECK VISUALS**.
- Diseño oscuro azul/negro adaptable a móvil.

## 1. Crear la base de datos
```bash
npx wrangler d1 create northside-db
```
Copia el `database_id` que devuelve y pégalo en `wrangler.toml`.

## 2. Crear tablas
```bash
npx wrangler d1 execute northside-db --file=schema.sql
```

## 3. Configurar administrador
En `wrangler.toml`, cambia `ADMIN_EMAIL` por el correo que usarás para registrarte como administrador.
El primer usuario con ese correo recibirá el rol `admin`.

## 4. Probar localmente
```bash
npm install
npm run dev
```

## 5. Publicar
```bash
npx wrangler deploy
```

## Notas importantes
- Cambia `database_id` antes de desplegar.
- El correo de administrador debe coincidir exactamente con `ADMIN_EMAIL`.
- El panel de administración aparece solo al iniciar sesión como admin.
- Para un sitio público real, configura un dominio propio y revisa las políticas de privacidad y moderación.
