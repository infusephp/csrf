<?php

/**
 * @package infuse/csrf
 * @author Jared King <j@jaredtking.com>
 * @link http://jaredtking.com
 * @copyright 2016 Jared King
 * @license MIT
 */

/* This configuration is used to run the tests */

return  [
  'app' => [
    'hostname' => 'example.com'
  ],
  'services' => [
    'csrf' => 'Infuse\Csrf\Csrf',
    'csrf_tokens' => 'Infuse\Csrf\CsrfTokens',
  ],
];
