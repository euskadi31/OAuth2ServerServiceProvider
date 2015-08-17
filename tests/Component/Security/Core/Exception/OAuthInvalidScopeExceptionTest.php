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

use Euskadi31\Component\Security\Core\Exception\OAuthInvalidScopeException;

class OAuthInvalidScopeExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $exception = new OAuthInvalidScopeException();

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('The requested scope is invalid, unknown, or malformed.', $exception->getMessage());
        $this->assertEquals(400, $exception->getStatusCode());
        $this->assertEquals('invalid_scope', $exception->getErrorCode());
        $this->assertEquals('API', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="API", error="invalid_scope", error_description="The requested scope is invalid, unknown, or malformed."'
        ], $exception->getHeaders());

        $exception = new OAuthInvalidScopeException('foo', 403, null, 'Test');

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('foo', $exception->getMessage());
        $this->assertEquals(403, $exception->getStatusCode());
        $this->assertEquals('invalid_scope', $exception->getErrorCode());
        $this->assertEquals('Test', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="Test", error="invalid_scope", error_description="foo"'
        ], $exception->getHeaders());
    }
}
