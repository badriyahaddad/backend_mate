<?php

namespace App\Http\Controllers;
use App\Http\Requests\LoginRequest;
use App\Models\user_otps;
use App\Models\users;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Storage;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Illuminate\Support\Facades\Log;

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
        return response()->json(['message' => 'The email does not exist.'], 404);
    }

    // Check if the password is correct
    if (!Hash::check($credentials['password'], $user->password)) {
        return response()->json(['message' => 'The password is incorrect.'], 401);
    }

    // If credentials are correct, authenticate the user
    if (Auth::attempt($credentials)) {
        try {
            // Generate Access Token (JWT Token)
            $accessToken = JWTAuth::fromUser($user);

            // Optionally, create a refresh token (long-lived token)
            $refreshToken = JWTAuth::fromUser($user, ['exp' => now()->addWeeks(2)->timestamp]);

            return response()->json([
                'message' => 'Login successful',
                'access_token' => $accessToken,  // Short-lived token (e.g., 1 hour)
                'refresh_token' => $refreshToken,  // Long-lived token (e.g., 2 weeks)
                'user' => $user,
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Could not create token',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    return response()->json(['message' => 'Login failed.'], 401);
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
//------------------------------------------ log out ---------------------------------------------------------
public function logout(Request $request)
{
    try {
        // Get the token from the request
        $token = JWTAuth::getToken();

        // Check if the token exists
        if (!$token) {
            return response()->json(['error' => 'Token not provided'], 400);
        }

        // Debugging: Output the payload of the token
        $payload = JWTAuth::getPayload($token)->toArray();
        Log::info('Payload:', $payload);

        // Invalidate the token
        JWTAuth::invalidate($token);

        return response()->json(['message' => 'Successfully logged out']);
    } catch (TokenExpiredException $e) {
        return response()->json(['error' => 'Token has already expired'], 401);
    } catch (TokenInvalidException $e) {
        Log::error('Invalid Token:', ['token' => $token]);
        return response()->json(['error' => 'Token is invalid'], 400);
    } catch (\Exception $e) {
        return response()->json(['error' => 'Failed to logout, please try again'], 500);
    }
}

public function refreshToken(Request $request)
{
    try {
        // Get the refresh token from the request header
        $refreshToken = $request->header('Authorization');

        // Attempt to refresh the token
        $newAccessToken = JWTAuth::refresh($refreshToken);

        return response()->json([
            'new_access_token' => $newAccessToken,
        ], 200);
    } catch (TokenExpiredException $e) {
        return response()->json(['error' => 'Refresh token expired'], 401);
    } catch (TokenInvalidException $e) {
        return response()->json(['error' => 'Invalid refresh token'], 400);
    }
}

}
