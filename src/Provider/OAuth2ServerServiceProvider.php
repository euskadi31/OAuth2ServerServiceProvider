<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Silex\Provider;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use LogicException;
use Euskadi31\Component\Security\Core\Authentication\Provider\OAuth2AuthenticationProvider;
use Euskadi31\Component\Security\Http\EntryPoint\OAuth2AuthenticationEntryPoint;
use Euskadi31\Component\Security\Http\Firewall\OAuth2AuthenticationListener;

/**
 * OAuth2 server integration for Silex.
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuth2ServerServiceProvider implements ServiceProviderInterface
{
    /**
     * {@inheritDoc}
     */
    public function register(Container $app)
    {
        if (!isset($app['security.token_storage'])) {
            throw new LogicException('You must register the SecurityServiceProvider to use the OAuth2ServerServiceProvider');
        }

        $app['oauth2.options'] = [
            'realm_name'        => 'Api',
            'grant_types'       => ['authorization_code'],
            'access_token_ttl'  => 172800
        ];

        $app['oauth2.access_token.provider'] = function($app) {
            throw new LogicException('The "access_token" provider entry is not registered.');
        };

        $app['oauth2.client.provider'] = function($app) {
            throw new LogicException('The "client" provider entry is not registered.');
        };

        $app['oauth2.scope.provider'] = function($app) {
            throw new LogicException('The "scope" provider entry is not registered.');
        };

        $app['oauth2.auth_code.provider'] = function($app) {
            throw new LogicException('The "auth_code" provider entry is not registered.');
        };

        // OAuth2 Authentication Provider
        $app['security.authentication_listener.factory.oauth2'] = $app->protect(function($name, $options) use ($app) {

            // define the authentication provider object
            $app['security.authentication_provider.' . $name . '.oauth2'] = function($app) {
                return new OAuth2AuthenticationProvider(
                    $app['security.user_provider.default'],
                    $app['security.user_checker'],
                    $app['oauth2.access_token.provider'],
                    $app['oauth2.options']['realm_name']
                );
            };

            // define the authentication listener object
            $app['security.authentication_listener.' . $name . '.oauth2'] = function($app) use ($name) {
                return new OAuth2AuthenticationListener(
                    $app['security.token_storage'],
                    $app['security.authentication_manager'],
                    $app['security.entry_point.' . $name . '.oauth2'],
                    isset($app['logger']) ? $app['logger'] : null,
                    $app['oauth2.options']['realm_name']
                );
            };

            /*$app['security.entry_point.' . $name . '.oauth2'] = function($app) {
                return new OAuth2AuthenticationEntryPoint(
                    $app['oauth2.options']['realm_name'],
                    isset($app['logger']) ? $app['logger'] : null
                );
            };*/

            return [
                // the authentication provider id
                'security.authentication_provider.' . $name . '.oauth2',
                // the authentication listener id
                'security.authentication_listener.' . $name . '.oauth2',
                // the entry point id
                'security.entry_point.' . $name . '.oauth2',
                // the position of the listener in the stack
                'pre_auth'
            ];

        });
    }
}
