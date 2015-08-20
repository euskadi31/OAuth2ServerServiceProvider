<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Core\Authentication\Provider;

use Euskadi31\Component\Security\Core\Authentication\Provider\OAuth2AuthenticationProvider;
use Symfony\Component\Security\Core\Exception\DisabledException;

class OAuth2AuthenticationProviderTest extends \PHPUnit_Framework_TestCase
{
    public function testAuthenticationProvider()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $this->assertInstanceOf('Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface', $provider);
    }

    public function testSupports()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\AbstractToken');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $this->assertTrue($provider->supports($tokenMock));
    }

    public function testAuthenticateWithBadToken()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\AbstractToken');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $this->assertNull($provider->authenticate($tokenMock));
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException
     * @expectedExceptionMessage The access token could not be found.
     */
    public function testAuthenticateWithNotFoundAccessToken()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue(null));

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenExpiredException
     * @expectedExceptionMessage The access token provided has expired.
     */
    public function testAuthenticateWithAccessTokenExpired()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(true));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenExpiredException
     * @expectedExceptionMessage The access token provided was revoked.
     */
    public function testAuthenticateWithAccessTokenRevoked()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(true));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException
     * @expectedExceptionMessage The access token could not be found.
     */
    public function testAuthenticateWithAccessTokenClientNotFound()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue(null));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException
     * @expectedExceptionMessage The access token could not be found.
     */
    public function testAuthenticateWithAccessTokenClientNotEnabled()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(false));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException
     * @expectedExceptionMessage The access token could not be found.
     */
    public function testAuthenticateWithAccessTokenClientLocked()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('isLocked')
            ->will($this->returnValue(true));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException
     * @expectedExceptionMessage The access token could not be found.
     */
    public function testAuthenticateWithBadUser()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $userMock                   = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenMock->expects($this->once())
            ->method('getUsername')
            ->will($this->returnValue('axel@domain.tld'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('isLocked')
            ->will($this->returnValue(false));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->with($this->equalTo('axel@domain.tld'))
            ->will($this->returnValue($userMock));

        $userCheckerMock->expects($this->once())
            ->method('checkPreAuth')
            ->with($this->equalTo($userMock))
            ->will($this->throwException(new DisabledException));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    public function testAuthenticateWithAccessToken()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $userMock                   = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $userMock->expects($this->once())
            ->method('getRoles')
            ->will($this->returnValue(['ROLE_USER']));

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('getId')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenMock->expects($this->once())
            ->method('getUsername')
            ->will($this->returnValue('axel@domain.tld'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('isLocked')
            ->will($this->returnValue(false));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->with($this->equalTo('axel@domain.tld'))
            ->will($this->returnValue($userMock));

        $userCheckerMock->expects($this->once())
            ->method('checkPreAuth')
            ->with($this->equalTo($userMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $token = $provider->authenticate($tokenMock);

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken', $token);

        $this->assertEquals('foo', $token->getAccessToken());
        $this->assertEquals($clientMock, $token->getClient());
        $this->assertEquals($userMock, $token->getUser());
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException
     * @expectedExceptionMessage The request is not signed.
     */
    public function testAuthenticateWithoutSignature()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('isLocked')
            ->will($this->returnValue(false));

        $clientMock->expects($this->once())
            ->method('isSignatureRequired')
            ->will($this->returnValue(true));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException
     * @expectedExceptionMessage The request signature we calculated does not match the signature you provided.
     */
    public function testAuthenticateWithBadSignature()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $signatureMock->expects($this->once())
            ->method('verify')
            ->will($this->returnValue(false));

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $tokenMock->expects($this->once())
            ->method('getSignature')
            ->will($this->returnValue('fooo'));

        $tokenMock->expects($this->exactly(2))
            ->method('isSigned')
            ->will($this->returnValue(true));

        $tokenMock->expects($this->once())
            ->method('getSignedUrl')
            ->will($this->returnValue('https://api.domain.com/v1/me'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('isLocked')
            ->will($this->returnValue(false));

        $clientMock->expects($this->exactly(2))
            ->method('isSignatureRequired')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('getSecret')
            ->will($this->returnValue('test'));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }


    public function testAuthenticateWithSignature()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken');
        $accessTokenMock            = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $userMock                   = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $signatureMock->expects($this->once())
            ->method('verify')
            ->will($this->returnValue(true));

        $userMock->expects($this->once())
            ->method('getRoles')
            ->will($this->returnValue(['ROLE_USER']));

        $tokenMock->expects($this->once())
            ->method('getAccessToken')
            ->will($this->returnValue('foo'));

        $tokenMock->expects($this->exactly(2))
            ->method('getSignature')
            ->will($this->returnValue('d12f9a9cf82fef1436caf54d5e7f8ab6796bdd10b32f80e77873ac535676ce0c'));

        $tokenMock->expects($this->exactly(2))
            ->method('isSigned')
            ->will($this->returnValue(true));

        $tokenMock->expects($this->once())
            ->method('getSignedUrl')
            ->will($this->returnValue('https://api.domain.com/v1/me'));

        $accessTokenMock->expects($this->once())
            ->method('getId')
            ->will($this->returnValue('foo'));

        $accessTokenMock->expects($this->once())
            ->method('isExpired')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('isRevoked')
            ->will($this->returnValue(false));

        $accessTokenMock->expects($this->once())
            ->method('getClient')
            ->will($this->returnValue('bar'));

        $accessTokenMock->expects($this->once())
            ->method('getUsername')
            ->will($this->returnValue('axel@domain.tld'));

        $accessTokenProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('foo'))
            ->will($this->returnValue($accessTokenMock));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('isLocked')
            ->will($this->returnValue(false));

        $clientMock->expects($this->exactly(2))
            ->method('isSignatureRequired')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('getSecret')
            ->will($this->returnValue('test'));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $userProviderMock->expects($this->once())
            ->method('loadUserByUsername')
            ->with($this->equalTo('axel@domain.tld'))
            ->will($this->returnValue($userMock));

        $userCheckerMock->expects($this->once())
            ->method('checkPreAuth')
            ->with($this->equalTo($userMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $token = $provider->authenticate($tokenMock);

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken', $token);

        $this->assertEquals('foo', $token->getAccessToken());
        $this->assertEquals($clientMock, $token->getClient());
        $this->assertEquals($userMock, $token->getUser());
    }



    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException
     * @expectedExceptionMessage The access token could not be found.
     */
    public function testAuthenticateWithClientNotFound()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->once())
            ->method('getClientId')
            ->will($this->returnValue('bar'));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue(null));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $provider->authenticate($tokenMock);
    }

    public function testAuthenticateWithClient()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenMock                  = $this->getMock('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $signatureMock              = $this->getMock('Euskadi31\Component\Security\Http\Signature\SignatureInterface');

        $tokenMock->expects($this->exactly(2))
            ->method('getClientId')
            ->will($this->returnValue('bar'));

        $clientMock->expects($this->once())
            ->method('isEnabled')
            ->will($this->returnValue(true));

        $clientMock->expects($this->once())
            ->method('isLocked')
            ->will($this->returnValue(false));

        $clientProviderMock->expects($this->once())
            ->method('get')
            ->with($this->equalTo('bar'))
            ->will($this->returnValue($clientMock));

        $provider = new OAuth2AuthenticationProvider(
            $userProviderMock,
            $userCheckerMock,
            $accessTokenProviderMock,
            $clientProviderMock,
            $signatureMock,
            'API'
        );

        $token = $provider->authenticate($tokenMock);

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken', $token);

        $this->assertEquals('bar', $token->getClientId());
        $this->assertEquals($clientMock, $token->getClient());
    }

}
