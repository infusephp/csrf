<?php

/**
 * @package infuse/csrf
 * @author Jared King <j@jaredtking.com>
 * @link http://jaredtking.com
 * @copyright 2016 Jared King
 * @license MIT
 */

namespace Infuse\Csrf;

use Infuse\HasApp;
use Infuse\Request;
use Infuse\Response;
use Symfony\Component\Security\Csrf\CsrfToken;

class CsrfMiddleware
{
    use HasApp;

    /**
     * @staticvar array
     */
    private static $protectedMethods = [
        'POST',
        'PUT',
        'DELETE',
        'PATCH',
    ];

    /**
     * @var string
     */
    private $prefix = 'csrf';

    /**
     * @var bool
     */
    private $singleUseTokens = true;

    /**
     * @var bool
     */
    private $enabled = true;

    /**
     * @var callable
     */
    private $failureCallable;

    /**
     * @var string|null $prefix
     */
    public function __construct($prefix = null)
    {
        if ($prefix !== null) {
            $this->prefix = $prefix;
        }
    }

    public function __invoke($req, $res, $next)
    {
        // Check if global CSRF protection is disabled
        if (!$this->enabled) {
            return $next($req, $res);
        }

        // Check if CSRF protection is disabled for the route
        $route = (array) array_value($this->app['routeInfo'], 1);
        $params = (array) array_value($route, 2);
        if (array_value($params, 'no_csrf')) {
            return $next($req, $res);
        }

        // Validate the CSRF token on protected request methods
        // i.e. POST, PUT, DELETE, PATCH...
        if (in_array($req->method(), self::$protectedMethods)) {
            $token = $this->getTokenFromRequest($req);
            if (!$this->validateToken($token)) {
                return $this->handleFailure($req, $res);
            }
        }

        // Generate a new CSRF token, every request
        $token = $this->generateToken();
        list($req, $res) = $this->attachToken($token, $req, $res);

        return $next($req, $res);
    }

    /**
     * Checks if CSRF protection is enabled.
     *
     * @return bool
     */
    public function enabled()
    {
        return $this->enabled;
    }

    /**
     * Enables CSRF protection. This might be used by other
     * middlewares to enable CSRF protection for certain routes.
     *
     * @return self
     */
    public function enable()
    {
        $this->enabled = true;

        return $this;
    }

    /**
     * Disables CSRF protection. This might be used by other
     * middlewares to disable CSRF protection for certain routes.
     *
     * @return self
     */
    public function disable()
    {
        $this->enabled = false;

        return $this;
    }

    /**
     * Gets the token id key.
     *
     * @return string
     */
    public function getTokenIdKey()
    {
        return $this->prefix.'_id';
    }

    /**
     * Gets the token value key.
     *
     * @return string
     */
    public function getTokenValueKey()
    {
        return $this->prefix.'_value';
    }

    /**
     * Gets the name of the token cookie.
     *
     * @return string
     */
    function getCookieName()
    {
        return $this->prefix.'_token';
    }

    /**
     * Gets the name of the CSRF token.
     *
     * @return string
     */
    function getHeaderName()
    {
        return 'X_CSRF_Token';
    }

    /**
     * Generates a CSRF token.
     *
     * @return CsrfToken
     */
    public function generateToken()
    {
        // Each new token uses a randomly generated ID
        // to allow multiple tokens to co-exist. This prevents
        // collisions when the user has multiple tabs open, since
        // tokens can only be used once.
        $id = uniqid($this->prefix);

        return $this->app['csrf_tokens']->getToken($id);
    }

    /**
     * Attachs a CSRF token to a request.
     *
     * @param CsrfToken $token
     * @param Request   $req
     * @param Response $res
     *
     * @return array array(Request, Response)
     */
    public function attachToken(CsrfToken $token, Request $req, Response $res)
    {
        $params = [
            $this->getTokenIdKey() => $token->getId(),
            $this->getTokenValueKey() => $token->getValue(),
        ];

        // set the token on the request
        $req = $req->setParams($params);

        // also set the token as a cookie
        $cookie = json_encode($params);
        $secure = $this->app['config']->get('app.ssl');
        $domain = '.'.$this->app['config']->get('app.hostname');
        $res = $res->setCookie($this->getCookieName(), $cookie, 0, '/', $domain, $secure, false);

        return [$req, $res];
    }

    /**
     * Extracts a CSRF token from the request.
     *
     * @param Request $req
     *
     * @return CsrfToken
     */
    function getTokenFromRequest(Request $req)
    {
        // fetch the token from the headers
        if ($header = $req->headers($this->getHeaderName())) {
            $token = json_decode($header, true);

            if (is_array($token)) {
                $id = array_value($token, $this->getTokenIdKey());
                $value = array_value($token, $this->getTokenValueKey());

                return new CsrfToken($id, $value);
            }
        }

        // fetch the token from the request body
        $id = $req->request($this->getTokenIdKey());
        $value = $req->request($this->getTokenValueKey());

        return new CsrfToken($id, $value);
    }

    /**
     * Validates a CSRF token.
     *
     * @param CsrfToken $token
     *
     * @return bool
     */
    public function validateToken(CsrfToken $token)
    {
        $id = $token->getId();
        if (!$id) {
            return false;
        }

        $csrf = $this->app['csrf_tokens'];
        $result = $csrf->isTokenValid($token);

        // Removes tokens from storage after first use
        if ($this->singleUseTokens) {
            $csrf->removeToken($id);
        }

        return $result;
    }

    /**
     * Renders the CSRF form HTML for a given request.
     *
     * @param Request $req
     *
     * @return string HTML
     */
    public function render(Request $req)
    {
        $idKey = $this->getTokenIdKey();
        $valueKey = $this->getTokenValueKey();

        $html = '<input type="hidden" name="'.$idKey.'" value="'.$req->params($idKey).'" />'."\n";
        $html .= '<input type="hidden" name="'.$valueKey.'" value="'.$req->params($valueKey).'" />';

        return $html;
    }

    /**
     * Registers a custom failure handler.
     *
     * @param callable $handler
     *
     * @return self
     */
    function onFailure(callable $handler) {
        $this->failureCallable = $handler;

        return $this;
    }

    /**
     * Builds a response when the CSRF check fails.
     *
     * @param Request  $req
     * @param Response $res
     *
     * @return Response
     */
    public function handleFailure(Request $req, Response $res)
    {
        if ($this->failureCallable) {
            return call_user_func($this->failureCallable, $req, $res);
        }

        if ($req->isJson()) {
            return $res->setCode(400)
                       ->json([
                            'type' => 'invalid_request',
                            'message' => 'Detected a possible CSRF attempt!'
                        ]);
        }

        return $res->setCode(400)
                   ->setContentType('text/plain')
                   ->setBody('Detected a possible CSRF attempt!');
    }
}
