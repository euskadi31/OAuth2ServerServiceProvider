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

use Euskadi31\Component\Security\GrantType\PasswordGrantType;
use Euskadi31\Component\Security\GrantType\GrantTypeInterface;
use Symfony\Component\HttpFoundation\ParameterBag;

class PasswordGrantTypeTest extends \PHPUnit_Framework_TestCase
{
    public function testInterface()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $encoderFactoryMock         = $this->getMock('Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface');

        $grantType = new PasswordGrantType($userProviderMock, 'main', $accessTokenProviderMock, $encoderFactoryMock);

        $this->assertInstanceOf('Euskadi31\Component\Security\GrantType\GrantTypeInterface', $grantType);
    }

    public function testName()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $encoderFactoryMock         = $this->getMock('Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface');

        $grantType = new PasswordGrantType($userProviderMock, 'main', $accessTokenProviderMock, $encoderFactoryMock);

        $this->assertEquals('password', $grantType->getName());
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException
     * @expectedExceptionMessage Missing username parameter.
     */
    public function testHandleWithoutUsernameParameter()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $encoderFactoryMock         = $this->getMock('Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface');
        $requestMock                = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');

        $requestMock->request = new ParameterBag;

        $grantType = new PasswordGrantType($userProviderMock, 'main', $accessTokenProviderMock, $encoderFactoryMock);

        $grantType->handle($requestMock, $clientMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException
     * @expectedExceptionMessage Missing password parameter.
     */
    public function testHandleWithoutPasswordParameter()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $encoderFactoryMock         = $this->getMock('Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface');
        $requestMock                = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');

        $requestMock->request = new ParameterBag;
        $requestMock->request->set('username', 'foo');

        $grantType = new PasswordGrantType($userProviderMock, 'main', $accessTokenProviderMock, $encoderFactoryMock);

        $grantType->handle($requestMock, $clientMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException
     * @expectedExceptionMessage Bad credentials.
     */
    public function testHandleWithBadCredentials()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $encoderFactoryMock         = $this->getMock('Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface');
        $passwordEncoderMock        = $this->getMock('Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface');
        $requestMock                = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $userMock                   = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');

        $userMock->expects($this->once())
            ->method('getPassword')
            ->will($this->returnValue('bar'));
        $userMock->expects($this->once())
            ->method('getSalt')
            ->will($this->returnValue('salt'));

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->will($this->returnValue($userMock));

        $encoderFactoryMock->expects($this->once())
            ->method('getEncoder')
            ->will($this->returnValue($passwordEncoderMock));

        $passwordEncoderMock->expects($this->once())
            ->method('isPasswordValid')
            ->with($this->equalTo('bar'), $this->equalTo('bar1'), $this->equalTo('salt'))
            ->will($this->returnValue(false));

        $requestMock->request = new ParameterBag;
        $requestMock->request->set('username', 'foo');
        $requestMock->request->set('password', 'bar1');

        $grantType = new PasswordGrantType($userProviderMock, 'main', $accessTokenProviderMock, $encoderFactoryMock);

        $grantType->handle($requestMock, $clientMock);
    }

    public function testHandle()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $encoderFactoryMock         = $this->getMock('Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface');
        $passwordEncoderMock        = $this->getMock('Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface');
        $requestMock                = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $userMock                   = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');

        $userMock->expects($this->once())
            ->method('getPassword')
            ->will($this->returnValue('bar'));
        $userMock->expects($this->once())
            ->method('getSalt')
            ->will($this->returnValue('salt'));

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->will($this->returnValue($userMock));

        $encoderFactoryMock->expects($this->once())
            ->method('getEncoder')
            ->will($this->returnValue($passwordEncoderMock));

        $passwordEncoderMock->expects($this->once())
            ->method('isPasswordValid')
            ->with($this->equalTo('bar'), $this->equalTo('bar'), $this->equalTo('salt'))
            ->will($this->returnValue(true));

        $accessTokenMock->expects($this->once())
            ->method('getId')
            ->will($this->returnValue('ZFgertgrtgRTGeez645Dfg'));

        $accessTokenMock->expects($this->once())
            ->method('getExpires')
            ->will($this->returnValue(0));

        $accessTokenProviderMock->expects($this->once())
            ->method('create')
            ->with($this->equalTo($userMock), $this->equalTo($clientMock), $this->equalTo(null))
            ->will($this->returnValue($accessTokenMock));

        $requestMock->request = new ParameterBag;
        $requestMock->request->set('username', 'foo');
        $requestMock->request->set('password', 'bar');

        $grantType = new PasswordGrantType($userProviderMock, 'main', $accessTokenProviderMock, $encoderFactoryMock);

        $response = $grantType->handle($requestMock, $clientMock);

        $this->assertEquals(json_encode([
            'access_token'  => 'ZFgertgrtgRTGeez645Dfg',
            'token_type'    => 'bearer',
            'expires_in'    => 0
        ]), $response->getContent());

        $this->assertTrue($response->headers->has('Content-Type'));
        $this->assertTrue($response->headers->has('Cache-Control'));
        $this->assertTrue($response->headers->has('Pragma'));

    }
}

