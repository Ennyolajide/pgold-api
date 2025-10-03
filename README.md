# Auth API (Laravel + Sanctum)

Email-OTP authentication API built with Laravel. Provides endpoints for user registration, email verification via OTP, login, profile management, and selfie uploads. All responses follow a consistent JSON envelope.

---

### 🚀 Quick Start
#### Install dependencies
```bash
composer install
cp .env.example .env
php artisan key:generate
```
#### Configure your database & mail in .env
#### Run migrations
```bash
php artisan migrate
```
#### Run the server
```bash
php artisan serve
```
#### Run tests:
```bash
php artisan test
```

---
## API Overview

#### Public Endpoints (Base path: /api)

| Method | Path                 | Description               |
| ------ | -------------------- | ------------------------- |
| POST   | `/auth/register`     | Register user & send OTP  |
| POST   | `/auth/verify-email` | Verify email with OTP     |
| POST   | `/auth/resend-otp`   | Resend OTP (60s throttle) |
| POST   | `/auth/login`        | Login & receive token     |

#### Protected Endpoints (Authorization: Bearer <token>)

| Method | Path            | Description              |
| ------ | --------------- | ------------------------ |
| GET    | `/users/me`     | Fetch authenticated user |
| POST   | `/users/selfie` | Upload selfie image      |

### Health

  * GET /api/ → Laravel version
  * GET /api/health → { "status": "ok" }

  ---
### Response Format
```json
// Success
{
  "status": "success",
  "data": { ... },
  "message": "Message here"
}

// Error
{
  "status": "error",
  "message": "What went wrong",
  "data": { ... } // optional
}
```
---

### OTP Policy
  * Testing (default): OTP is logged, not emailed.

  * Testing (opt-in): If config('mail.send_in_tests') === true, emails are sent.

  * Local/Dev/Prod: Always emails OTP.

  * OTPs expire in 5 minutes.
  
  * Resend is throttled to once every 60 seconds.

---
### Request Examples
#### Register
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"janedoe","full_name":"Jane Doe","phone":"1234567890","email":"jane@example.com","password":"secret123"}'
```
#### Verify Email
```bash
curl -X POST http://localhost:8000/api/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","otp":"123456"}'
```
#### Login
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","password":"secret123"}'
```
#### Me (authenticated)
```bash
curl http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <TOKEN>"
```
#### Upload Selfie
```bash
curl -X POST http://localhost:8000/api/users/selfie \
  -H "Authorization: Bearer <TOKEN>" \
  -F "selfie=@/path/to/photo.jpg"
```

---
### Validation Rules
  * Register: username, full_name, phone, email (unique), password(min:6) | Optional: referral_code, heard_about

  * Verify Email: email, otp (numeric)

  * Resend OTP: email (throttled)

  * Selfie: image, max 5MB

---
### 🧪 Testing

Feature tests live in tests/Feature/AuthFlowTest.php. They cover:

  * OTP behavior (send/log, resend, throttle)

  * Register & verify email

  * Login (token issuance)

  * Profile (/users/me)

  * Selfie upload

Run all tests: 
```bash 
php artisan test 
```
✔ Add a screenshot here showing all tests passing.

---
### Security Notes
  * Passwords hashed with bcrypt.

  * OTPs short-lived (5 minutes).

  * Selfies stored on public disk (/storage/selfies/...).

  + For sensitive use, consider private storage + signed URLs.

---
### Routes Summary
| Method | Path                     | Description             |
|--------|--------------------------|-------------------------|
| POST   | /api/auth/register       | Create user + send OTP  |
| POST   | /api/auth/verify-email   | Verify OTP              |
| POST   | /api/auth/resend-otp     | Resend OTP (throttled)  |
| POST   | /api/auth/login          | Login + token           |
| GET    | /api/users/me            | Current user            |
| POST   | /api/users/selfie        | Upload selfie           |


