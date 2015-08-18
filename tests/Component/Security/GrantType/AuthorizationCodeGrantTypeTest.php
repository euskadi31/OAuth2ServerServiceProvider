<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\GrantType;

use Euskadi31\Component\Security\GrantType\AuthorizationCodeGrantType;

class AuthorizationCodeGrantTypeTest extends \PHPUnit_Framework_TestCase
{
    public function testInterface()
    {
        $grantType = new AuthorizationCodeGrantType();

        $this->assertInstanceOf('Euskadi31\Component\Security\GrantType\GrantTypeInterface', $grantType);
    }

    public function testName()
    {
        $grantType = new AuthorizationCodeGrantType();

        $this->assertEquals('authorization_code', $grantType->getName());
    }

    public function testHandle()
    {
        $requestMock    = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $clientMock     = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');

        $grantType = new AuthorizationCodeGrantType();

        $response = $grantType->handle($requestMock, $clientMock);

        $this->assertInstanceOf('Symfony\Component\HttpFoundation\Response', $response);
    }
}

