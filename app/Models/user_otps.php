<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class user_otps extends Model
{

    use HasFactory;

    protected $fillable = [
        'user_id',
        'otp_code',
        'otp_expires_at',
    ];

    // Define relationship with User model
    public function user()
    {
        return $this->belongsTo(users::class, 'user_id');
    }

    protected $table = 'user_otps';
}