<?php

namespace Laravel\Sanctum;

trait HasApiTokens {
    public function createToken($name, array $abilities = ['*']) {
        // Dummy method to satisfy Intelephense.
    }
}
