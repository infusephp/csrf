<?php

/**
 * @package infuse/csrf
 * @author Jared King <j@jaredtking.com>
 * @link http://jaredtking.com
 * @copyright 2016 Jared King
 * @license MIT
 */

namespace Infuse\Csrf;

use Symfony\Component\Security\Csrf\CsrfTokenManager;

class CsrfTokens
{
    public function __invoke()
    {
        return new CsrfTokenManager();
    }
}
