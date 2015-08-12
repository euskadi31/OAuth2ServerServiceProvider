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
    }
}
