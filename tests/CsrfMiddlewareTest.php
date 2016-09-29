<?php

/**
 * @package infuse/csrf
 * @author Jared King <j@jaredtking.com>
 * @link http://jaredtking.com
 * @copyright 2016 Jared King
 * @license MIT
 */

use Infuse\Csrf\CsrfMiddleware;
use Infuse\Request;
use Infuse\Response;
use Infuse\Test;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManager;

class CsrfMiddlewareTest extends PHPUnit_Framework_TestCase
{
    public function testDI()
    {
        $this->assertInstanceOf('Infuse\Csrf\CsrfMiddleware', Test::$app['csrf']);
        $this->assertEquals('csrftest_id', Test::$app['csrf']->getTokenIdKey());
        $this->assertInstanceOf('Symfony\Component\Security\Csrf\CsrfTokenManager', Test::$app['csrf_tokens']);
    }

    function testEnableDisable()
    {
        $middleware = $this->getMiddleware();

        $this->assertTrue($middleware->enabled());
        $middleware->disable();
        $this->assertFalse($middleware->enabled());
        $middleware->enable();
        $this->assertTrue($middleware->enabled());
    }

    function testGetTokenIdKey()
    {
        $middleware = $this->getMiddleware();
        $this->assertEquals('csrf_test_id', $middleware->getTokenIdKey());

        $middleware = new CsrfMiddleware();
        $this->assertEquals('csrf_id', $middleware->getTokenIdKey());
    }

    function testGetTokenValueKey()
    {
        $middleware = $this->getMiddleware();
        $this->assertEquals('csrf_test_value', $middleware->getTokenValueKey());
    }

    function testGetCookieName()
    {
        $middleware = $this->getMiddleware();
        $this->assertEquals('csrf_test_token', $middleware->getCookieName());
    }

    function testGetHeaderName()
    {
        $middleware = $this->getMiddleware();
        $this->assertEquals('X_CSRF_Token', $middleware->getHeaderName());
    }

    function testGenerateToken()
    {
        $middleware = $this->getMiddleware();

        $token = $middleware->generateToken();
        $this->assertInstanceOf('Symfony\Component\Security\Csrf\CsrfToken', $token);

        $token2 = $middleware->generateToken();

        $this->assertInstanceOf('Symfony\Component\Security\Csrf\CsrfToken', $token2);
        $this->assertNotEquals($token->getId(), $token2->getId());
        $this->assertNotEquals($token->getValue(), $token2->getValue());
    }

    function testAttachToken()
    {
        $middleware = $this->getMiddleware();
        $req = new Request;
        $res = new Response;

        $token = new CsrfToken('12345', '6789');

        $this->assertEquals([$req, $res], $middleware->attachToken($token, $req, $res));

        $this->assertEquals('12345', $req->params('csrf_test_id'))
        ;
        $this->assertEquals('6789', $req->params('csrf_test_value'));

        $expected = [
            '{"csrf_test_id":"12345","csrf_test_value":"6789"}',
            0,
            '/',
            '.example.com',
            false,
            false
        ];
        $this->assertEquals($expected, $res->cookies('csrf_test_token'));
    }

    function testGetTokenFromRequestBody()
    {
        $middleware = $this->getMiddleware();
        $req = Request::create('/', 'POST', ['csrf_test_id' => '12345', 'csrf_test_value' => '6789']);

        $token = $middleware->getTokenFromRequest($req);
        $this->assertInstanceOf('Symfony\Component\Security\Csrf\CsrfToken', $token);

        $this->assertEquals('12345', $token->getId());
        $this->assertEquals('6789', $token->getValue());
    }

    function testGetTokenFromRequestHeader()
    {
        $middleware = $this->getMiddleware();
        $header = '{"csrf_test_id":"12345","csrf_test_value":"6789"}';
        $req = Request::create('/', 'POST', [], [], [], ['HTTP_X_CSRF_TOKEN' => $header]);

        $token = $middleware->getTokenFromRequest($req);
        $this->assertInstanceOf('Symfony\Component\Security\Csrf\CsrfToken', $token);

        $this->assertEquals('12345', $token->getId());
        $this->assertEquals('6789', $token->getValue());
    }

    function testGetTokenFromRequestHeaderEmpty()
    {
        $middleware = $this->getMiddleware();
        $header = 'blah';
        $req = Request::create('/', 'POST', [], [], [], ['HTTP_X_CSRF_TOKEN' => $header]);

        $token = $middleware->getTokenFromRequest($req);
        $this->assertInstanceOf('Symfony\Component\Security\Csrf\CsrfToken', $token);

        $this->assertEquals('', $token->getId());
        $this->assertEquals('', $token->getValue());
    }

    function testValidateTokenEmpty()
    {
        $middleware = $this->getMiddleware();

        $token = new CsrfToken('', '');
        $this->assertFalse($middleware->validateToken($token));
    }

    function testValidateToken()
    {
        $middleware = $this->getMiddleware();
        $token = new CsrfToken('id', 'value');

        Test::$app['csrf_tokens']->shouldReceive('isTokenValid')
                                 ->andReturn(true);
        Test::$app['csrf_tokens']->shouldReceive('removeToken')
                                 ->once();

        $this->assertTrue($middleware->validateToken($token));
    }

    function testRender()
    {
        $req = new Request;
        $req->setParams([
            'csrf_test_id' => '12345',
            'csrf_test_value' => '6789',
        ]);

        $middleware = $this->getMiddleware();

        $expected = '<input type="hidden" name="csrf_test_id" value="12345" />
<input type="hidden" name="csrf_test_value" value="6789" />';
        $this->assertEquals($expected, $middleware->render($req));
    }

    function testHandleFailure()
    {
        $req = new Request;
        $res = new Response;

        $middleware = $this->getMiddleware();
        $res = $middleware->handleFailure($req, $res);
        
        $this->assertInstanceOf('Infuse\Response', $res);
        $this->assertEquals(400, $res->getCode());
    }

    function testHandleFailureJson()
    {
        $req = Request::create('/', 'GET', [], [], [], ['HTTP_ACCEPT' => 'application/json']);
        $res = new Response;

        $middleware = $this->getMiddleware();
        $res = $middleware->handleFailure($req, $res);
        
        $this->assertInstanceOf('Infuse\Response', $res);
        $this->assertEquals(400, $res->getCode());
    }

    function testHandleFailureCustom()
    {
        $req = new Request;
        $res = new Response;

        $middleware = $this->getMiddleware();
        $middleware->onFailure(function($req, $res) {
            return $res->setCode(500);
        });

        $res = $middleware->handleFailure($req, $res);
        
        $this->assertInstanceOf('Infuse\Response', $res);
        $this->assertEquals(500, $res->getCode());
    }

    function testInvokeDisabled()
    {
        $middleware = $this->getMiddleware();
        $req = Request::create('/', 'POST');
        $res = new Response;

        $middleware->disable();

        $next = function($req, $res) {
            return 'yay';
        };

        $this->assertEquals('yay', $middleware($req, $res, $next));
    }

    function testInvokeRouteDisabled()
    {
        $middleware = $this->getMiddleware();
        $req = Request::create('/', 'POST');
        $res = new Response;

        Test::$app['routeInfo'] = [[], ['', '', ['no_csrf' => true]]];

        $next = function($req, $res) {
            return 'yay';
        };

        $this->assertEquals('yay', $middleware($req, $res, $next));
    }

    function testInvokeGetRequest()
    {
        Test::$app['routeInfo'] = [[], []];
        $middleware = $this->getMiddleware();
        $req = Request::create('/', 'GET');
        $res = new Response;

        $next = function($req, $res) {
            return 'yay';
        };

        $this->assertEquals('yay', $middleware($req, $res, $next));

        $this->assertGreaterThan(0, strlen($req->params('csrf_test_id')));
        $this->assertGreaterThan(0, strlen($req->params('csrf_test_value')));
    }

    function testInvokePostRequest()
    {
        Test::$app['routeInfo'] = [[], []];
        $middleware = $this->getMiddleware();
        $req = Request::create('/', 'POST', ['csrf_test_id' => '1234', 'csrf_test_value' => '5678']);
        $res = new Response;

        Test::$app['csrf_tokens']->shouldReceive('isTokenValid')
                                 ->andReturn(true);
        Test::$app['csrf_tokens']->shouldReceive('removeToken')
                                 ->once();

        $next = function($req, $res) {
            return 'yay';
        };

        $this->assertEquals('yay', $middleware($req, $res, $next));

        $this->assertGreaterThan(0, strlen($req->params('csrf_test_id')));
        $this->assertGreaterThan(0, strlen($req->params('csrf_test_value')));
    }

    function testInvokePostRequestFail()
    {
        Test::$app['routeInfo'] = [[], []];
        $middleware = $this->getMiddleware();
        $req = Request::create('/', 'POST');
        $res = new Response;

        $next = function($req, $res) {
            return 'yay';
        };

        $this->assertEquals($res, $middleware($req, $res, $next));
        $this->assertEquals(400, $res->getCode());
    }

    private function getMiddleware()
    {
        $manager = Mockery::mock();
        $manager->shouldReceive('getToken')
                ->andReturnUsing(function($id) {
                    return new CsrfToken($id, rand());
                });
        unset(Test::$app['csrf_tokens']);
        Test::$app['csrf_tokens'] = $manager;

        $middleware = new CsrfMiddleware('csrf_test');
        $middleware->setApp(Test::$app);

        return $middleware;
    }
}
