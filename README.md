# Enterprise SSO Server

Корпоративный SSO сервер с аутентификацией через Active Directory.

## Возможности

- Аутентификация через Active Directory (LDAPS)
- Трехэтапный вход (логин → пароль → подтверждение)
- Загрузка фото профиля из AD
- Автоматическая темная тема
- OAuth2/OpenID Connect провайдер
- Связывание устройств через LDAP

## Установка

### Требования

- Node.js 16+
- Active Directory сервер (LDAPS)

### Быстрый старт

```bash
git clone https://github.com/shinichiroisumi/sso-server.git
cd sso-server
npm run setup
```

## OAuth2/OpenID Connect

Сервер поддерживает OAuth2 и OpenID Connect для интеграции с приложениями.

### Регистрация клиента

```bash
curl -X POST http://localhost:3000/oauth2/clients/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["https://myapp.com/oauth/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile email"
  }'
```

### OIDC Discovery URL

```
http://localhost:3000/oauth2/.well-known/openid-configuration
```