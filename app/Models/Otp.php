<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Otp extends Model
{
    /**
     * The table associated with the model.
     * (Optional since Laravel would pluralize Otp → otps correctly)
     */
    protected $table = 'otps';

    /**
     * The attributes that are mass assignable.
     * Only expose fields we want to create/update via ::create() or ::updateOrCreate().
     */
    protected $fillable = [
        'email',
        'code',
        'expires_at',
        'last_sent_at',
    ];

    /**
     * The attributes that should be cast.
     * This makes it easier to compare times with Carbon in controllers.
     */
    protected $casts = [
        'expires_at'   => 'datetime',
        'last_sent_at' => 'datetime',
    ];
}