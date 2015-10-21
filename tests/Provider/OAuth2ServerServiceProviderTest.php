<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Silex\Provider;

use Euskadi31\Silex\Provider\OAuth2ServerServiceProvider;
use Symfony\Component\HttpFoundation\Request;
use Silex\Application;

class OAuth2ServerProviderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException LogicException
     */
    public function testRegisterWithoutSecurityService()
    {
        $app = new Application;

        $app->register(new OAuth2ServerServiceProvider);
    }

    public function testRegister()
    {
        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $this->assertEquals([
            'realm_name'        => 'Api',
            'grant_types'       => ['authorization_code', 'password'],
            'access_token_ttl'  => 172800
        ], $app['oauth2.options']);
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage The "access_token" provider entry is not registered.
     */
    public function testAccessTokenProvider()
    {
        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $app['oauth2.access_token.provider'];
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage The "client" provider entry is not registered.
     */
    public function testClientProvider()
    {
        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $app['oauth2.client.provider'];
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage The "scope" provider entry is not registered.
     */
    public function testScopeProvider()
    {
        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $app['oauth2.scope.provider'];
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage The "auth_code" provider entry is not registered.
     */
    public function testAuthCodeProvider()
    {
        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $app['oauth2.auth_code.provider'];
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage Invalid grant_type "bad".
     */
    public function testGrantTypeCollectionWithGrantTypeNotFound()
    {
        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $app['oauth2.options'] = [
            'realm_name'        => 'Api',
            'grant_types'       => ['bad', 'authorization_code', 'password'],
            'access_token_ttl'  => 172800
        ];

        $app['oauth2.grant_types'];
    }

    /**
     * @expectedException LogicException
     * @expectedExceptionMessage The GrantTypeCollection accept only GrantTypeInterface instance.
     */
    public function testGrantTypeCollectionWithBadGrantType()
    {
        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $app['oauth2.grant_type.authorization_code'] = function($app) {
            return new \stdClass();
        };

        $app['oauth2.grant_types'];
    }


    public function testGrantTypeCollection()
    {
        $authCodeGrantTypeMock = $this->getMock('Euskadi31\Component\Security\GrantType\GrantTypeInterface');
        $authCodeGrantTypeMock->method('getName')
            ->will($this->returnValue('authorization_code'));

        $passwordGrantTypeMock = $this->getMock('Euskadi31\Component\Security\GrantType\GrantTypeInterface');
        $passwordGrantTypeMock->method('getName')
            ->will($this->returnValue('password'));

        $app = new Application;
        $app['security.token_storage'] = true;

        $app->register(new OAuth2ServerServiceProvider);

        $app['oauth2.grant_type.authorization_code'] = function($app) use ($authCodeGrantTypeMock) {
            return $authCodeGrantTypeMock;
        };

        $app['oauth2.grant_type.password'] = function($app) use ($passwordGrantTypeMock) {
            return $passwordGrantTypeMock;
        };

        $collection = $app['oauth2.grant_types'];

        $this->assertTrue($collection->offsetExists('authorization_code'));
        $this->assertTrue($collection->offsetExists('password'));
    }

    public function testListener()
    {
        $userProviderMock           = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $accessTokenProviderMock    = $this->getMock('Euskadi31\Component\Security\Storage\AccessTokenProviderInterface');
        $encoderFactoryMock         = $this->getMock('Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface');
        $userCheckerMock            = $this->getMock('Symfony\Component\Security\Core\User\UserCheckerInterface');
        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $tokenStorageMock           = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authenticationManagerMock  = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');

        $app = new Application;

        $app['security.token_storage'] = function() use ($tokenStorageMock) {
            return $tokenStorageMock;
        };

        $app->register(new OAuth2ServerServiceProvider);

        $app['security.user_provider.default'] = function() use ($userProviderMock) {
            return $userProviderMock;
        };

        $app['oauth2.access_token.provider'] = function() use ($accessTokenProviderMock) {
            return $accessTokenProviderMock;
        };

        $app['security.encoder_factory'] = function() use ($encoderFactoryMock) {
            return $encoderFactoryMock;
        };

        $app['security.user_checker'] = function() use ($userCheckerMock) {
            return $userCheckerMock;
        };

        $app['oauth2.client.provider'] = function() use ($clientProviderMock) {
            return $clientProviderMock;
        };

        $app['security.authentication_manager'] = function() use ($authenticationManagerMock) {
            return $authenticationManagerMock;
        };

        $factory = $app['security.authentication_listener.factory.oauth2']('api', []);

        $this->assertEquals([
            'security.authentication_provider.api.oauth2',
            'security.authentication_listener.api.oauth2',
            'security.entry_point.api.oauth2',
            'pre_auth'
        ], $factory);

        $signature = $app['oauth2.signature'];

        $this->assertInstanceOf('Euskadi31\Component\Security\Http\Signature\SignatureInterface', $signature);

        $passwordGrantType = $app['oauth2.grant_type.password'];

        $this->assertInstanceOf('Euskadi31\Component\Security\GrantType\PasswordGrantType', $passwordGrantType);

        $authorizationCodeGrantType = $app['oauth2.grant_type.authorization_code'];

        $this->assertInstanceOf('Euskadi31\Component\Security\GrantType\AuthorizationCodeGrantType', $authorizationCodeGrantType);

        $provider = $app['security.authentication_provider.api.oauth2'];

        $this->assertInstanceOf('Euskadi31\Component\Security\Core\Authentication\Provider\OAuth2AuthenticationProvider', $provider);

        $listener = $app['security.authentication_listener.api.oauth2'];

        $this->assertInstanceOf('Euskadi31\Component\Security\Http\Firewall\OAuth2AuthenticationListener', $listener);

        $entryPoint = $app['security.entry_point.api.oauth2'];

        $this->assertInstanceOf('Euskadi31\Component\Security\Http\EntryPoint\OAuth2AuthenticationEntryPoint', $entryPoint);
    }
}
