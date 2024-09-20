<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Room extends Model
{
    use HasFactory;
    protected $fillable = ['title', 'admin_id', 'number_of_users'];
    public function admin()
    {
        return $this->belongsTo(users::class, 'admin_id');
    }
    public function users()
    {
        return $this->belongsToMany(users::class, 'room_user')
                    ->withPivot('role');
    }
}