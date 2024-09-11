<?php
use Illuminate\Support\Facades\Mail;

use App\Http\Controllers\TestController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where  can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
Route::get('/home', function () {
    return view('home');
});

Route::controller(TestController::class)->prefix('name')->group(function () {
    Route::post('store', 'firstAction') ;
    Route::get('show', 'showNames');
     Route::delete('delete/{id}', 'deleteName');
Route::put('update/{id}', 'updateName');
Route::get('search',  'searchNames');
});
Route::controller(AuthController::class)->prefix('auth')->group(function () {
    Route::post('signup', 'register')->withoutMiddleware('auth:api');
    Route::post('login', 'login')->withoutMiddleware(['auth']);
    Route::post('forgot-password',  'forgotPassword')->withoutMiddleware('auth:api');
    Route::post('reset-password', 'resetPassword')->withoutMiddleware('auth:api');
    Route::middleware('auth:api')->get('showusers', 'index');
    Route::get('showtoken', 'handle');
});
Route::get('test-email', function () {
    Mail::raw('Test email body', function ($message) {
        $message->to('badriya.al.haddad.it.3915@gmail.com')->subject('Test Email');
    });
});