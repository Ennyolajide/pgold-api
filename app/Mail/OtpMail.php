<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class OtpMail extends Mailable
{
    use Queueable, SerializesModels;

    public string $otp;

    /**
     * Accept the OTP value at construction so we can pass it into the view.
     */
    public function __construct(string $otp)
    {
        $this->otp = $otp;
    }

    /**
     * Build the message.
     * Here we choose a Blade view for flexibility (can include HTML formatting).
     */
    public function build()
    {
        return $this->subject('Your Verification Code')
                    ->view('mail.otp')     // resources/views/mail/otp.blade.php
                    ->with(['otp' => $this->otp]);
    }
}
