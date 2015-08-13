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

/**
 * AuthorizeControllerProvider
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class AuthorizeControllerProvider implements ControllerProviderInterface
{
    /**
     * @param  Silex\Application $app
     * @return Silex\ControllerCollection
     */
    public function connect(Application $app)
    {
        $controllers = $app['controllers_factory'];

        $controllers->get('/oauth/authorize', function(Request $request) use ($app) {

            return '';
        });

        return $controllers;
    }
}
