# Glamora website and admin panel

One small Node.js server that runs three things:

* the public Glamora website (`/`)
* a password-protected admin panel (`/admin`)
* the database and image storage behind both

There is nothing to install except Node.js. The project has **no dependencies** (`npm install` is not needed).

## 1. Run it on your computer

1. Install **Node.js 22.13 or newer** from https://nodejs.org (choose "LTS" or "Current", version 22 or higher).
2. Open this folder in a terminal.
3. Copy `.env.example` to `.env` and edit it. Set your own `ADMIN_USERNAME` and a long `ADMIN_PASSWORD` (at least 10 characters, with letters and numbers).
4. Start it:
   ```
   node server.js
   ```
5. Open http://localhost:3000 for the website and http://localhost:3000/admin to sign in.

The first time it starts it creates the database, creates your administrator account from `.env`, and loads Glamora's current collections, products, photos and articles so nothing starts empty.

## 2. Your administrator account

* The account is created **once**, from `ADMIN_USERNAME` / `ADMIN_PASSWORD`. Restarting the server never overwrites your password.
* The password is stored only as a salted scrypt hash. It is never stored or logged in plain text.
* There is no public sign-up page.
* **Change your password** any time in the admin: *Change Password*. This also signs out other sessions.
* **Forgot your password?** Put a new `ADMIN_PASSWORD` in `.env` and run `npm run set-admin` (or `node server.js set-admin`) on the server. This is the only way to reset it, and it signs out every session.
* After the first start you may delete `ADMIN_PASSWORD` from `.env`.

## 3. What you can manage in /admin

Dashboard (live counts) · Products (add, edit, delete, draft/publish/archive, search, filters, pagination, SKU check, sale price) · Collections · Categories · Homepage (hero banner, section on/off, featured products and their order, brand story, newsletter text) · About Page · Blog Posts (block editor, preview, draft/published, slug redirects) · Media Library (upload, replace, copy URL, delete unused) · Contact Messages (status, search, reply by email, delete) · Website Settings (name, logo, favicon, colours, announcement bar, contact details, social links, footer) · Change Password.

Changes are saved to the database and appear on the website the next time a visitor loads or refreshes a page. No restart is needed.

## 4. Putting it online

Use any host that can run a Node.js 22+ app **and** keeps a persistent disk (for example Render, Railway, Fly.io or a VPS). Files saved on temporary storage disappear on restart, so this matters.

1. Upload this folder (without `.env`, `data/`).
2. Set these environment variables on the host: `NODE_ENV=production`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `DATA_DIR=/path/to/persistent/disk`, and `PORT` if the host asks for one.
3. Start command: `node server.js`.
4. Serve the site over **HTTPS** (every host above does this for you). With `NODE_ENV=production` cookies are marked Secure and HSTS is sent.
5. Back up the `DATA_DIR` folder regularly (it contains `glamora.db` and `uploads/`).

## 5. Security built in

* Server-side sessions; random token stored hashed; cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` in production.
* Every admin page and every admin API call is checked on the server. Unauthenticated visitors are redirected to `/admin/login`.
* Login attempts are rate-limited (5 failures per username and 30 per address in 15 minutes).
* State-changing admin requests need a custom header and a matching origin (CSRF protection).
* All input is validated on the server; all database access uses bound parameters (no SQL injection).
* Uploads accept only real JPEG, PNG and WebP files (checked by content, not file name), up to 8 MB, saved under random names.
* Blog content is stored as structured blocks and rendered with escaping, so scripts cannot be injected.
* Security headers (CSP, no-sniff, frame blocking, referrer policy) are sent on every response.
* The contact form has a honeypot field and a rate limit (5 messages per hour per address).

## 6. Good to know

* The newsletter box on the website is not connected to a mailing list yet and says so. The contact form is fully connected: messages appear in *Contact Messages*.
* The product detail page (`#/products/...`) is not built yet and shows "Coming soon".
* Changes appear when a page is loaded or refreshed. There is no "preview before publishing" screen: use Draft status on products and posts to keep work private until you publish.
* The contact form stores messages in the database; it does not send email notifications.
* The in-memory login rate limit resets if the server restarts and is per server (fine for one server).
* The website URLs use `#` routes (for example `/#/collections/women`). Search engines do not read these well. Moving to server-rendered pages is a future step.

## 7. Files

```
server.js            the server (website, admin, API, database, security)
admin/index.html     the admin panel
public/index.html    the Glamora website
seed/                Glamora's existing content and photos, loaded on first start
data/                created at runtime: glamora.db and uploads/ (back this up)
.env.example         settings template
```
