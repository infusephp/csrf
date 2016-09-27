<?php

/**
 * @package infuse/csrf
 * @author Jared King <j@jaredtking.com>
 * @link http://jaredtking.com
 * @copyright 2016 Jared King
 * @license MIT
 */

namespace Infuse\Csrf;

class Csrf
{
    public function __invoke($app)
    {
    	$prefix = $app['config']->get('csrf.prefix');
        $middleware = new CsrfMiddleware($prefix);
        $middleware->setApp($app);

        return $middleware;
    }
}
