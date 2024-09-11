<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use App\Models\User;
use App\Models\user_otps;
use App\Models\users;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Mail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Closure;
use Laravel\Sanctum\HasApiTokens;
use Carbon\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);    }


//----------------------------------------sign up ----------------------------------------
public function register(Request $request)
{
    // Validate the incoming request data
    $validated = $request->validate([
        'name' => 'required|string|max:255',
        'age' => 'required|integer',
        'email' => 'required|string|email|max:255|unique:users_mate,email',
        'password' => 'required|string|min:8|confirmed',
    ]);

    // Create the user in 'users_mate' table
    $user = users::create([
        'name' => $validated['name'],
        'age' => $validated['age'],
        'email' => $validated['email'],
        'password' => Hash::make($validated['password']),
    ]);

    // Store the user data in a file in the 'storage/app' directory
    Storage::put('user_data.json', json_encode($user));

    // Return a success message
    return response()->json(['message' => 'User registered successfully'], 201);
}
//----------------------------------------login----------------------------------------
public function login(LoginRequest $request)
{
    // Get validated data
    $credentials = $request->validated();

    // Find user by email
    $user = users::whereRaw('LOWER(email) = ?', [strtolower($credentials['email'])])->first();

    // If user does not exist, return error response
    if (!$user) {
        return response()->json([
            'message' => 'The email does not exist.'
        ], 404);
    }

    // Check if the password is correct
    if (!Hash::check($credentials['password'], $user->password)) {
        return response()->json([
            'message' => 'The password is incorrect.'
        ], 401);
    }

    // If credentials are correct, authenticate the user
    if (Auth::attempt($credentials)) {
        // Generate token or session (depending on your authentication method)
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => 'Login successful',
            'token' => $token,
            'user' => $user,
        ], 200);
    }

    return response()->json([
        'message' => 'Login failed.'
    ], 401);
}


//----------------------------------------forget----------------------------------------
public function forgotPassword(Request $request)
{
    // Step 1: Validate the email input
    $request->validate(['email' => 'required|email']);

    // Step 2: Find the user by email
    $user = users::where('email', strtolower($request->email))->first();

    if (!$user) {
        return response()->json(['message' => 'Email does not exist'], 404);
    }

    // Step 3: Generate a random OTP and store it in the   OTP  table
    $otp = rand(100000, 999999); // Generate a 6-digit OTP

    // Check if the   user already has an OTP and update it
    $userOtp = $user->otp;
    if ($userOtp) {
        $userOtp->otp_code = $otp;
        $userOtp->otp_expires_at = now()->addMinutes(10); // Set OTP to expire in 10 minutes
        $userOtp->save();
    } else {
        // Create a new OTP record if none exists
        $userOtp = user_otps::create([
            'user_id' => $user->id,
            'otp_code' => $otp,
            'otp_expires_at' => now()->addMinutes(10),
        ]);
    }

    // Step 4: Send the OTP via email
    Mail::raw("Your OTP code is $otp. It will expire in 10 minutes.", function ($message) use ($user) {
        $message->to($user->email)
            ->subject('Password Reset OTP');
    });

    // Step 5: Return a success message
    return response()->json(['message' => 'OTP sent to your email'], 200);
}

//---------------------------------------- Method to handle password reset----------------------------------------
public function resetPassword(Request $request)
{
    // Validate the OTP and the email
    $request->validate([
        'email' => 'required|email',
        'otp' => 'required|integer',
        'password' => 'required|string|min:6|confirmed',
    ]);

    // Find the user by email
    $user = users::where('email', $request->email)->first();

    if (!$user) {
        return response()->json(['message' => 'Email not found'], 404);
    }

    // Fetch the OTP record associated with the user
    $userOtp = $user->otp;

    // Check if OTP exists, matches, and is still valid
    if (!$userOtp || $userOtp->otp_code != $request->otp || now()->greaterThan($userOtp->otp_expires_at)) {
        return response()->json(['message' => 'Invalid OTP or OTP has expired'], 400);
    }

    // If the OTP is valid, update the user's password
    $user->password = bcrypt($request->password);
    $user->save();

    // Clear OTP record after successful password reset
    $userOtp->delete();

    return response()->json(['message' => 'Password reset successfully'], 200);
}

}