<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Http\EntryPoint;

use Euskadi31\Component\Security\Http\EntryPoint\OAuth2AuthenticationEntryPoint;

class OAuth2AuthenticationEntryPointTest extends \PHPUnit_Framework_TestCase
{
    public function testEntryPoint()
    {
        $loggerMock = $this->getMock('Psr\Log\LoggerInterface');

        $entryPoint = new OAuth2AuthenticationEntryPoint('Test', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');

        $exceptionMock = new \Euskadi31\Component\Security\Core\Exception\OAuthPermissionsException();

        $response = $entryPoint->start($requestMock, $exceptionMock);

        $this->assertInstanceOf('Symfony\Component\HttpFoundation\Response', $response);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('Bearer realm="Test", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token."', $response->headers->get('WWW-Authenticate'));
    }
}
