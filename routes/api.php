<?php

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\UserController;



//Route::get('/', fn ($router) => $router->app->version());
Route::get('health', fn () => response()->json(['status' => 'ok']));
    
Route::controller(AuthController::class)->group(
    function () {
        Route::post('/auth/login', 'login');
        Route::post('/auth/register', 'register');        // send OTP
        Route::post('/auth/resend-otp', 'resendOtp');      // throttle + resend
        Route::post('/auth/verify-email', 'verifyEmail');  // verify OTP
    }
);

// Sanctum token

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/users/me', [AuthController::class, 'me']);  
    //Route::get('/user', fn (Request $request) => $request->user());
    Route::post('/users/selfie', [AuthController::class, 'uploadSelfie']);  // selfie upload
});
