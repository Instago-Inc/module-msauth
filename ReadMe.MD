# module/msauth - V8 module

msauth provides a simple way to handle Microsoft sign-in flows so workflows can access Microsoft services without wiring every OAuth step by hand. It keeps the experience friendly by guiding users through device code sign-in and reusing saved tokens when possible.

Use it as the common entry point for Microsoft auth in this V8 environment. For more details about the platform, visit https://instago.ai.

## Technical reference

### Exports

- `configure(opts)`
- `auth(opts)` -> access token string or `''`
- `getToken(opts)` -> `{ status, tokens?, device?, error? }`
- `ensureAuthenticated(opts)` -> same as `getToken`
- `ensureTokens(opts)` -> alias for `ensureAuthenticated`
- `getAuthToken(opts)` -> alias for `auth`
- `refresh(opts)` -> token object
- `clientCredentialsToken(opts)` -> token object
- `clear(opts)`
- `shouldNotifyMsAuth(opts)` -> boolean

### Usage

```js
const msauth = require('msauth@latest');

msauth.configure({
  tenant: 'common',
  clientId: env.get('msauth.clientId'),
  scope: 'mail,calendar'
});

const res = await msauth.getToken();
if (res.status === 'ok') {
  const accessToken = res.tokens.access_token;
  // use accessToken in Graph calls
} else if (res.status === 'pending') {
  // show device instructions to the user
  const device = res.device || {};
  console.log('Visit', device.verification_uri, 'and enter', device.user_code);
}
```

```js
const msauth = require('msauth@latest');

const token = await msauth.auth({
  scope: 'https://graph.microsoft.com/.default',
  mode: 'app',
  clientId: env.get('msauth.clientId'),
  clientSecret: env.get('msauth.clientSecret')
});
```

### Configuration

Required env:
- `msauth.tenant` - Azure AD tenant ID or `common`.
- `msauth.clientId` - Azure AD application (client) ID.

Optional env:
- `msauth.clientSecret` - Client secret (needed for client credentials or refresh with secret).
- `msauth.scope` - Space/comma separated scopes or scope aliases (e.g., `mail,todo`).
- `msauth.mode` - Auth mode: `device` | `app` | `client`.
- `msauth.debug` - Enable debug logging (`true`/`false`).

Options (most functions accept these):
- `tenant`, `clientId`, `clientSecret`, `scope`
- `scopes` or `services` as aliases for `scope`
- `mode` or `authMode`
- `useClientSecret` (boolean) to force secret in device/refresh
- `maxPollAttempts` (number) for device polling

Scope aliases:
- `mail`, `mail.readonly`
- `calendar`, `calendar.readonly`
- `contacts`, `contacts.readonly`
- `todo`, `todo.readonly`
- `files`, `files.readonly`
- `sharepoint`, `sharepoint.readonly`
- `user.read`
- `all` or `*` to expand to all mapped scopes

### Examples

```js
const msauth = require('msauth@latest');

const res = await msauth.ensureAuthenticated({ scope: 'files.readonly' });
if (res.status === 'ok') {
  console.log('token ready');
} else if (res.status === 'pending' && msauth.shouldNotifyMsAuth(res.device)) {
  console.log('Complete sign-in:', res.device.verification_uri, res.device.user_code);
}
```
