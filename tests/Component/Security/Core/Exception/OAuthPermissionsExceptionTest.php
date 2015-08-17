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

use Euskadi31\Component\Security\Core\Exception\OAuthPermissionsException;

class OAuthPermissionsExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $exception = new OAuthPermissionsException();

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('The request requires higher privileges than provided by the access token.', $exception->getMessage());
        $this->assertEquals(403, $exception->getStatusCode());
        $this->assertEquals('insufficient_scope', $exception->getErrorCode());
        $this->assertEquals('API', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="API", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token."'
        ], $exception->getHeaders());

        $exception = new OAuthPermissionsException('foo', 404, null, ['email'], 'Test');

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('foo', $exception->getMessage());
        $this->assertEquals(404, $exception->getStatusCode());
        $this->assertEquals('insufficient_scope', $exception->getErrorCode());
        $this->assertEquals('Test', $exception->getRealmName());
        $this->assertEquals(['email'], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="Test", error="insufficient_scope", error_description="foo", scope="email"'
        ], $exception->getHeaders());
    }

    public function testGetMessageKey()
    {
        $exception = new OAuthPermissionsException();

        $this->assertEquals('The request requires higher privileges than provided by the access token.', $exception->getMessageKey());
    }
}
