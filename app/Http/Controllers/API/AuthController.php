<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\API\BaseController as BaseController;
use App\Models\Otp;
use App\Models\User;
use App\Mail\OtpMail;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

/**
 * AuthController (API)
 *
 * Response envelope follows BaseController:
 *  - Success: sendResponse($data, $message)
 *  - Error:   sendError($message, $errors = [], $status = 4xx/5xx)
 *
 * Notes:
 * - OTPs expire in 5 minutes; resends are throttled to once per 60 seconds.
 * - Email delivery policy:
 *      testing (default):   LOG OTP (no external dependency)
 *      testing (opt-in):    if config('mail.send_in_tests') === true → send via Mail::to(...)
 *      local/dev/prod:      send via Mail::to(...)
 * - Uses Sanctum personal access tokens for API auth.
 */
class AuthController extends BaseController
{
    /** @var int OTP validity window (seconds) */
    private int $otpExpirySeconds = 5 * 60; // 5 minutes

    /** @var int OTP resend cooldown (seconds) */
    private int $resendCooldown = 60;       // 60 seconds

    /** Generate a secure 6-digit OTP. */
    private function generateOtp(): string
    {
        return (string) app()->environment('develop','local') ? '123456': random_int(100000, 999999);
    }

    /** Shape a public, non-sensitive view of a User for API responses. */
    private function publicUser(User $u): array
    {
        return [
            'id' => $u->id,
            'username' => $u->username,
            'full_name' => $u->full_name,
            'phone' => $u->phone,
            'email' => $u->email,
            'referral_code' => $u->referral_code,
            'heard_about' => $u->heard_about,
            'selfie' => $u->selfie,
            'emailVerifiedAt' => $u->email_verified_at?->toIso8601String(),
            'created_at' => $u->created_at?->toIso8601String(),
            'updated_at' => $u->updated_at?->toIso8601String(),
        ];
    }

    /**
     * Deliver OTP:
     * - In "testing" (default): log OTP so tests remain fast & infra-free.
     * - If config('mail.send_in_tests') === true (inside tests): actually send.
     * - In "local/dev/production": actually send via configured mail transport.
     */
    private function deliverOtp(string $email, string $otp): void
    {
        $isTesting = app()->environment('testing');
        $sendInTests = (bool) config('mail.send_in_tests', false);

        if ($isTesting && !$sendInTests) {
            // Avoid external services during automated tests.
            info("OTP for {$email}: {$otp}");
            return;
        }

        try {
            Mail::to($email)->send(new OtpMail($otp));
        } catch (\Throwable $e) {
            Log::error('Failed to send OTP email', [
                'email' => $email,
                'otp' => $otp,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * POST /api/auth/register
     * Creates an unverified user, generates and stores OTP, delivers OTP (email/log).
     */
    public function register(Request $request): JsonResponse
    {
        // Keep validation explicit for a coding test; mirrors your Node required fields.
        $v = Validator::make($request->all(), [
            'username' => ['required', 'string', 'max:255', 'unique:users,username'],
            'full_name' => ['required', 'string', 'max:255'],
            'phone' => ['required', 'string', 'max:40'],
            'email' => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'string', 'min:6'],
            'referral_code' => ['nullable', 'string', 'max:255'],
            'heard_about' => ['nullable', 'string', 'max:255'],
        ]);



        if ($v->fails()) {
            return $this->sendError('Validation Error.', $v->errors(), 422);
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);

        // Never store plain-text passwords.
        $user = User::create($input);

        // Prepare/update OTP row for this email.
        $otp = $this->generateOtp();
        Otp::updateOrCreate(
            ['email' => $user->email],
            [
                'code' => $otp,
                'last_sent_at' => now(),
                'expires_at' => now()->addSeconds($this->otpExpirySeconds),
            ]
        );

        // Deliver OTP following the policy above.
        $this->deliverOtp($user->email, $otp);

        return $this->sendResponse(['email' => $user->email], 'User registered. OTP sent to email.');
    }

    /**
     * POST /api/auth/verify-email
     * Confirms OTP, marks user as verified, deletes the OTP record.
     */
    public function verifyEmail(Request $request): JsonResponse
    {
        $v = Validator::make($request->all(), [
            'email' => ['required', 'email'],
            'otp' => ['required', 'numeric'],
        ]);

        if ($v->fails()) {
            return $this->sendError('Validation Error.', $v->errors(), 422);
        }

        $email = $v->validated()['email'];
        $otpInput = $v->validated()['otp'];

        $record = Otp::where('email', $email)->first();
        if (!$record) {
            return $this->sendError('OTP not found', [], 404);
        }

        if (now()->greaterThan($record->expires_at)) {
            $record->delete();
            return $this->sendError('OTP expired', [], 410);
        }

        if ($record->code !== $otpInput) {
            return $this->sendError('Invalid OTP', [], 401);
        }

        $user = User::where('email', $email)->first();
        if (!$user) {
            // Should not happen normally; clean up and fail gracefully.
            $record->delete();
            return $this->sendError('User not found', [], 404);
        }

        $user->email_verified_at = now();
        $user->save();
        $record->delete();

        return $this->sendResponse(['user' => $this->publicUser($user)], 'Email verified');
    }

    /**
     * POST /api/auth/resend-otp
     * Enforces a 60s throttle; returns 429 + Retry-After if called too soon.
     */
    public function resendOtp(Request $request): JsonResponse
    {
        $v = Validator::make($request->all(), [
            'email' => ['required', 'email'],
        ]);

        if ($v->fails()) {
            return $this->sendError('Validation Error.', $v->errors(), 422);
        }

        $email = $v->validated()['email'];
        $user = User::where('email', $email)->first();

        if (!$user) {
            return $this->sendError('User not found', [], 404);
        }

        if ($user->email_verified_at) {
            return $this->sendError('Email already verified', [], 400);
        }

        $record = Otp::firstOrNew(['email' => $email]);
        $now = now();

        // Throttle logic: only allow resend every 60 seconds.
        if ($record->last_sent_at && $record->last_sent_at->diffInSeconds(now()) < $this->resendCooldown) {
            $retryAfter = $now->diffInSeconds($record->last_sent_at) - $this->resendCooldown;

            // Craft response to include Retry-After header (helps clients back off correctly).
            return response()
                ->json([
                    'status' => 'error',
                    'message' => 'Please wait before requesting another OTP',
                    'data' => ['retryAfterSeconds' => $retryAfter],
                ], 429)
                ->header('Retry-After', (string) $retryAfter);
        }

        $code = $this->generateOtp();
        // New OTP replaces any previous value; extend expiry.
        $record->update([
            'code' => $code,
            'last_sent_at' => $now,
            'expires_at' => $now->copy()->addSeconds($this->otpExpirySeconds),
        ]);

        $this->deliverOtp($email, $code);

        return $this->sendResponse([
            'email' => $email,
            'expiresInSeconds' => $this->otpExpirySeconds,
            'retryAfterSeconds' => $this->resendCooldown,
        ], 'OTP resent to email.');
    }

    /**
     * POST /api/auth/login
     * Validates credentials and issues a Sanctum personal access token.
     */
    public function login(Request $request): JsonResponse
    {
        $v = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if ($v->fails()) {
            return $this->sendError('Validation Error.', $v->errors(), 422);
        }

        if (Auth::attempt($request->all())) {
            $user = Auth::user();
            $token = $user->createToken('auth')->plainTextToken;

            return $this->sendResponse([
                'token' => $token,
                'user' => $this->publicUser($user),
            ], 'User login successfully.');
        } else {
            return $this->sendError('Unauthorised.', ['error' => 'Invalid credentials'], 401);
        }
    }

    /**
     * GET /api/users/me   (auth:sanctum)
     * Returns the authenticated user's public profile.
     */
    public function me(Request $request): JsonResponse
    {
        /** @var User|null $user */
        $user = $request->user();

        if (!$user) {
            return $this->sendError('Unauthorised.', ['error' => 'No authenticated user'], 401);
        }

        return $this->sendResponse(['user' => $this->publicUser($user)], 'Profile fetched.');
    }

    /**
     * POST /api/users/selfie   (auth:sanctum)
     * Accepts an image file under "selfie"; stores to public disk and saves the public URL.
     */
    public function uploadSelfie(Request $request): JsonResponse
    {
        /** @var User|null $user */
        $user = $request->user();

        if (!$user) {
            return $this->sendError('Unauthorised.', ['error' => 'No authenticated user'], 401);
        }

        $v = Validator::make($request->all(), [
            // "image" rule prevents text disguised as an image; 5MB limit for safety.
            'selfie' => ['required', 'image', 'max:5120'],
        ]);

        if ($v->fails()) {
            return $this->sendError('Validation Error.', $v->errors(), 422);
        }

        // Requires: php artisan storage:link  → /storage maps to public disk
        $path = $request->file('selfie')->store('selfies', 'public');
        $url = Storage::url($path);

        $user->selfie = $url;
        $user->save();

        return $this->sendResponse(['selfie' => $user->selfie], 'Selfie uploaded');
    }
}
