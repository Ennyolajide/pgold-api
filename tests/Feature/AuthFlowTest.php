<?php

namespace Tests\Feature;

use App\Mail\OtpMail;
use App\Models\Otp;
use App\Models\User;
use Faker\Factory as FakerFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class AuthFlowTest extends TestCase
{
    use RefreshDatabase;

    /** @var \Faker\Generator */
    protected $faker;

    protected function setUp(): void
    {
        parent::setUp();

        // Fast, isolated disk for file assertions
        Storage::fake('public');

        // Fresh faker each test to avoid unique collisions
        $this->faker = FakerFactory::create();
    }

    /** Helper: realistic registration payload */
    private function regPayload(): array
    {
        return [
            'username'      => $this->faker->unique()->userName(),
            'full_name'     => $this->faker->name(),
            'phone'         => $this->faker->numerify('##########'),
            'email'         => $this->faker->unique()->safeEmail(),
            'password'      => 'secret123',
            'referral_code' => strtoupper($this->faker->bothify('???###')),
            'heard_about'   => $this->faker->randomElement(['internet','friend','ad']),
        ];
    }

    /* =========================================================================
     | EMAIL BEHAVIOR (no Pest)
     | default in tests: log only; opt-in with config('mail.send_in_tests', true)
     ========================================================================= */

    public function test_by_default_in_tests_otp_is_not_emailed(): void
    {
        Mail::fake(); // guardrail: nothing should be sent by default in tests

        $payload = $this->regPayload();

        $this->postJson('/api/auth/register', $payload)
            ->assertOk()
            ->assertJson(['status' => 'success']);

        Mail::assertNothingSent();
    }

    public function test_tests_can_opt_in_to_email_delivery_and_assert_OtpMail_was_sent(): void
    {
        config(['mail.send_in_tests' => true]); // enable send path in tests
        Mail::fake();

        $payload = $this->regPayload();

        $this->postJson('/api/auth/register', $payload)
            ->assertOk()
            ->assertJson(['status' => 'success']);

        Mail::assertSent(OtpMail::class, 1);
        Mail::assertSent(OtpMail::class, function (OtpMail $m) {
            return true; // could assert subject/view if needed
        });
    }

    public function test_resend_otp_emails_code_when_send_in_tests_flag_enabled(): void
    {
        config(['mail.send_in_tests' => true]);
        Mail::fake();

        $payload = $this->regPayload();

        $this->postJson('/api/auth/register', $payload)->assertOk();

        // ⏱️ Jump time forward past the 60s cooldown
        $this->travel(61)->seconds();
        
        $this->postJson('/api/auth/resend-otp', ['email' => $payload['email']])
            ->assertOk()
            ->assertJson(['status' => 'success']);

        Mail::assertSent(OtpMail::class, 2); // one for register + one for resend
    }

    /* =========================================================================
     | CORE FLOW TESTS
     ========================================================================= */

    public function test_register_sends_otp_and_creates_user_in_db(): void
    {
        $payload = $this->regPayload();

        $this->postJson('/api/auth/register', $payload)
            ->assertOk()
            ->assertJson([
                'status'  => 'success',
                'message' => 'User registered. OTP sent to email.',
            ])
            ->assertJsonPath('data.email', $payload['email']);

        $this->assertDatabaseHas('users', [
            'email' => $payload['email'],
            'username' => $payload['username'],
        ]);
        $this->assertDatabaseHas('otps',  ['email' => $payload['email']]);
    }

    public function test_verify_email_with_correct_otp(): void
    {
        $payload = $this->regPayload();
        $this->postJson('/api/auth/register', $payload)->assertOk();

        $otp = Otp::where('email', $payload['email'])->first();
        info('xx', [
            'email' => $payload['email'],
            'otp'   => $otp->code,
        ]);
        $this->assertNotNull($otp, 'Expected OTP row to exist after register');

        $this->postJson('/api/auth/verify-email', data: [
            'email' => $payload['email'],
            'otp'   => $otp->code,
        ])
        ->assertOk()
        ->assertJson([
            'status'  => 'success',
            'message' => 'Email verified',
        ])
        ->assertJsonStructure(['data' => ['user' => ['email', 'username', 'full_name']]]);

        $this->assertNull(Otp::where('email', $payload['email'])->first(), 'OTP row should be deleted');
        $this->assertNotNull(User::where('email', $payload['email'])->value('email_verified_at'));
    }

    public function test_verify_email_fails_with_wrong_otp(): void
    {
        $payload = $this->regPayload();
        $this->postJson('/api/auth/register', $payload)->assertOk();

        $this->postJson('/api/auth/verify-email', [
            'email' => $payload['email'],
            'otp'   => '000000', // wrong on purpose
        ])
        ->assertStatus(401)
        ->assertJson(['status' => 'error', 'message' => 'Invalid OTP']);
    }

    public function test_resend_otp_enforces_throttle_and_returns_retry_after_header(): void
    {
        $payload = $this->regPayload();
        $this->postJson('/api/auth/register', $payload)->assertOk();

        $this->postJson('/api/auth/resend-otp', ['email' => $payload['email']])
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertJson([
                'status'  => 'error',
                'message' => 'Please wait before requesting another OTP',
            ]);
    }

    public function test_login_returns_sanctum_token_and_user_object(): void
    {
        $user = User::factory()->create([
            'username'          => 'jane',
            'full_name'         => 'Jane Roe',
            'phone'             => '9876543210',
            'email'             => 'jane@example.com',
            'password'          => Hash::make('secret123'),
            'email_verified_at' => now(),
        ]);

        $resp = $this->postJson('/api/auth/login', [
            'email'    => 'jane@example.com',
            'password' => 'secret123',
        ])
        ->assertOk()
        ->assertJson([
            'status'  => 'success',
            // Matches your controller message text:
            'message' => 'User login successfully.',
        ])
        ->assertJsonStructure(['data' => ['token', 'user' => ['email','username','full_name']]]);

        $this->assertNotEmpty(data_get($resp->json(), 'data.token'));
    }

    public function test_users_me_returns_public_user_when_authenticated(): void
    {
        $user = User::factory()->create([
            'username'          => 'mike',
            'full_name'         => 'Mike Foo',
            'phone'             => '0000000000',
            'email'             => 'mike@example.com',
            'password'          => Hash::make('secret123'),
            'email_verified_at' => now(),
        ]);

        $token = $user->createToken('auth')->plainTextToken;

        $this->withHeader('Authorization', 'Bearer ' . $token)
            ->getJson('/api/users/me')
            ->assertOk()
            ->assertJson(['status' => 'success'])
            ->assertJsonPath('data.user.email', 'mike@example.com')
            ->assertJsonMissingPath('data.user.password');
    }

    public function test_upload_selfie_stores_file_and_returns_public_url(): void
    {
        $user = User::factory()->create([
            'username'          => 'selfieuser',
            'full_name'         => 'Selfie User',
            'phone'             => '1112223333',
            'email'             => 'selfie@example.com',
            'password'          => Hash::make('secret123'),
            'email_verified_at' => now(),
        ]);

        $token = $user->createToken('auth')->plainTextToken;

        $file = UploadedFile::fake()->image('me.jpg', 600, 600);

        $resp = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->postJson('/api/users/selfie', ['selfie' => $file])
            ->assertOk()
            ->assertJson([
                'status'  => 'success',
                'message' => 'Selfie uploaded',
            ]);

        $url = data_get($resp->json(), 'data.selfie');
        $this->assertNotEmpty($url);
        $this->assertStringStartsWith('/storage/', $url);

        $basename = basename(parse_url($url, PHP_URL_PATH));
        Storage::disk('public')->assertExists('selfies/' . $basename);

        $this->assertEquals($url, $user->fresh()->selfie);
    }
}
