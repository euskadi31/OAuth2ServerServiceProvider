<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Silex\Controller;

use Silex\Application;
use Silex\Api\ControllerProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException;
use Euskadi31\Component\Security\Core\Exception\OAuthInvalidClientException;
use Euskadi31\Component\Security\Core\Exception\OAuthUnauthorizedClientException;

/**
 * TokenControllerProvider
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class TokenControllerProvider implements ControllerProviderInterface
{
    /**
     * @param  Silex\Application $app
     * @return Silex\ControllerCollection
     */
    public function connect(Application $app)
    {
        $controllers = $app['controllers_factory'];

        $controllers->post('/oauth/token', function(Request $request) use ($app) {

            $grantType  = $request->request->get('grant_type');
            $clientId   = $request->server->get('PHP_AUTH_USER', $request->request->get('client_id'));
            $secret     = $request->server->get('PHP_AUTH_PW', $request->request->get('client_secret'));

            if (empty($clientId)) {
                throw new OAuthInvalidRequestException('Missing client_id parameter.');
            }

            if (empty($grantType)) {
                throw new OAuthInvalidRequestException('Missing grant_type parameter.');
            }

            $client = $app['oauth2.client.provider']->get($clientId);

            if (empty($client)) {
                throw new OAuthInvalidClientException('Unknown client');
            }

            if (!empty($secret) && !hash_equals($client->getSecret(), $secret)) {
                throw new OAuthUnauthorizedClientException();
            }

            $grantType = $app['oauth2.grant_types']->get($grantType);

            if (!in_array($grantType->getName(), $client->getGrantTypes())) {
                throw new OAuthUnauthorizedClientException();
            }

            return $grantType->handle($request, $client);
        });

        return $controllers;
    }
}
