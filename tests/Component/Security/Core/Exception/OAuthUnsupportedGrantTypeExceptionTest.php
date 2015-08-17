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

use Euskadi31\Component\Security\Core\Exception\OAuthUnsupportedGrantTypeException;

class OAuthUnsupportedGrantTypeExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $exception = new OAuthUnsupportedGrantTypeException();

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('The authorization grant type is not supported by the authorization server.', $exception->getMessage());
        $this->assertEquals(400, $exception->getStatusCode());
        $this->assertEquals('unsupported_grant_type', $exception->getErrorCode());
        $this->assertEquals('API', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="API", error="unsupported_grant_type", error_description="The authorization grant type is not supported by the authorization server."'
        ], $exception->getHeaders());

        $exception = new OAuthUnsupportedGrantTypeException('foo', 403, null, 'Test');

        $this->assertEquals('foo', $exception->getMessage());
        $this->assertEquals(403, $exception->getStatusCode());
        $this->assertEquals('unsupported_grant_type', $exception->getErrorCode());
        $this->assertEquals('Test', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="Test", error="unsupported_grant_type", error_description="foo"'
        ], $exception->getHeaders());
    }
}
