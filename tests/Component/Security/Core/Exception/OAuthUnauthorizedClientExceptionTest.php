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

use Euskadi31\Component\Security\Core\Exception\OAuthUnauthorizedClientException;

class OAuthUnauthorizedClientExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testException()
    {
        $exception = new OAuthUnauthorizedClientException();

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('The authenticated client is not authorized to use this authorization grant type.', $exception->getMessage());
        $this->assertEquals(401, $exception->getStatusCode());
        $this->assertEquals('unauthorized_client', $exception->getErrorCode());
        $this->assertEquals('API', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="API", error="unauthorized_client", error_description="The authenticated client is not authorized to use this authorization grant type."'
        ], $exception->getHeaders());

        $exception = new OAuthUnauthorizedClientException('foo', 403, null, 'Test');

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface', $exception);

        $this->assertEquals('foo', $exception->getMessage());
        $this->assertEquals(403, $exception->getStatusCode());
        $this->assertEquals('unauthorized_client', $exception->getErrorCode());
        $this->assertEquals('Test', $exception->getRealmName());
        $this->assertEquals([], $exception->getScopes());
        $this->assertEquals([
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => 'Bearer realm="Test", error="unauthorized_client", error_description="foo"'
        ], $exception->getHeaders());
    }
}
