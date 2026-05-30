# Enterprise SSO Server

Корпоративный SSO (Single Sign-On) сервер с аутентификацией через Active Directory.

## Возможности

- Аутентификация через Active Directory (LDAPS)
- Трехэтапный вход (логин → пароль → подтверждение)
- Загрузка фото профиля из AD
- Автоматическая темная тема (следует за системой)
- JWT токены в httpOnly cookies
- Поддержка нескольких приложений

## Технологии

- Node.js
- Express
- Active Directory (LDAPS)
- JWT

## Установка

### Требования

- Node.js 16+
- Active Directory сервер (LDAPS)

### Быстрый старт

```bash
git clone -b microsoft https://github.com/shinichiroisumi/sso-server.git
cd sso-server

//Установите зависимости
npm install

//Сгенерировать JWT ключ
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

//Настроить .env
nano .env

//Запуск
npm start
