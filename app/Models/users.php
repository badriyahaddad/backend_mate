<?php

namespace App\Models;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use App\Models\user_otps;
class users extends Authenticatable implements JWTSubject
{
    protected $fillable = [
        'name',
        'age',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }

    // Relationship to UserOtp model
    public function otp()
    {
        return $this->hasOne(user_otps::class, 'user_id');
    }

    protected $table = 'users_mate';
    use HasApiTokens, HasFactory, Notifiable;
}