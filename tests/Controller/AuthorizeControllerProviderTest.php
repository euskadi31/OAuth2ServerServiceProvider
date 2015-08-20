<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Silex\Controller;

use Euskadi31\Silex\Controller\AuthorizeControllerProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Silex\Application;
use Silex\WebTestCase;
use Exception;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\Debug\Exception\FlattenException;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class AuthorizeControllerProviderTest extends WebTestCase
{
    public function createApplication()
    {
        $app = new ApplicationTest();
        $app['route_class'] = 'Euskadi31\Silex\Controller\RouteTest';
        $app['debug'] = true;

        //unset($app['exception_handler']);

        $app->mount('/', new AuthorizeControllerProvider());

        $app->error(function(Exception $exception, $code) use ($app) {
            $e = FlattenException::create($exception);

            $headers = [];

            if ($exception instanceof HttpExceptionInterface) {
                $headers = $exception->getHeaders();
                $code = $exception->getStatusCode();
            } else {
                $code = $exception->getCode();
            }

            if ($code < 100 || $code >= 600) {
                $code = 500;
            }

            $error = [
                'error' => [
                    'message'   => $exception->getMessage(),
                    'type'      => join('', array_slice(explode('\\', get_class($exception)), -1)),
                    'code'      => $code
                ]
            ];

            if ($this->app['debug']) {
                $error['error']['exception'] = $e->toArray();
            }

            return new Response($app->json($error, $code, $headers));
        });

        return $app;
    }

    public function testAuthorize()
    {
        $client = $this->createClient();
        $client->request('POST', '/oauth/authorize');

        $response = $client->getResponse();

        $this->assertTrue($response->isClientError());
    }
}

class RouteTest extends \Silex\Route
{
    use \Silex\Route\SecurityTrait;
}

class ApplicationTest extends Application
{
    use \Silex\Application\SecurityTrait;
}
