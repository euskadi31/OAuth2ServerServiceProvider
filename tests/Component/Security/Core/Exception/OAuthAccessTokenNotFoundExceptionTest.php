<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Core\Exception;

use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException;

class OAuthAccessTokenNotFoundExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $exception = new OAuthAccessTokenNotFoundException();

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('The access token could not be found.', $exception->getMessage());
        $this->assertEquals(401, $exception->getStatusCode());
        $this->assertEquals('invalid_token', $exception->getErrorCode());
        $this->assertEquals('API', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="API", error="invalid_token", error_description="The access token could not be found."'
        ], $exception->getHeaders());

        $exception = new OAuthInvalidAccessTokenException('foo', 403, null, 'Test');

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('foo', $exception->getMessage());
        $this->assertEquals(403, $exception->getStatusCode());
        $this->assertEquals('invalid_token', $exception->getErrorCode());
        $this->assertEquals('Test', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="Test", error="invalid_token", error_description="foo"'
        ], $exception->getHeaders());
    }

    public function testGetMessageKey()
    {
        $exception = new OAuthAccessTokenNotFoundException();

        $this->assertEquals('The access token could not be found.', $exception->getMessageKey());
    }
}
