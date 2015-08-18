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

use Euskadi31\Silex\Controller\TokenControllerProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Silex\Application;
use Silex\WebTestCase;
use Exception;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\Debug\Exception\FlattenException;

class TokenControllerProviderTest extends WebTestCase
{
    public function createApplication()
    {
        $response = new Response(json_encode([
            'access_token' => 'foo',
            'token_type' => 'bearer',
            'expires_in' => 0
        ]));

        $clientProviderMock         = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');
        $clientMock                 = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');
        $grantTypeCollectionMock    = $this->getMock('Euskadi31\Component\Security\GrantType\GrantTypeCollection');
        $passwordGrantTypeMock      = $this->getMockBuilder('Euskadi31\Component\Security\GrantType\PasswordGrantType')
            ->disableOriginalConstructor()
            ->getMock();

        $passwordGrantTypeMock->method('getName')
            ->will($this->returnValue('password'));

        $passwordGrantTypeMock->method('handle')
            ->will($this->returnValue($response));

        $clientMock->method('getGrantTypes')
            ->will($this->returnValue(['password']));

        $clientMock->method('getSecret')
            ->will($this->returnValue('bar'));

        $clientProviderMock->method('get')
            ->will($this->returnValue($clientMock));

        $grantTypeCollectionMock->method('get')
            ->will($this->returnValue($passwordGrantTypeMock));

        $app = new Application();
        $app['debug'] = true;

        //unset($app['exception_handler']);

        $app->mount('/', new TokenControllerProvider());

        $app['oauth2.client.provider'] = function() use ($clientProviderMock) {
            return $clientProviderMock;
        };

        $app['oauth2.grant_types'] = function() use ($grantTypeCollectionMock) {
            return $grantTypeCollectionMock;
        };

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

    protected function parseResponse($response)
    {
        $content = $response->getContent();

        $pos = strpos($content, "\r\n\r\n");

        if ($pos >= 0) {
            return substr($content, $pos + 4);
        }

        return $content;
    }

    public function testTokenWithoutClientId()
    {
        $client = $this->createClient();
        $client->request('POST', '/oauth/token');

        $response = $client->getResponse();
        $content = json_decode($this->parseResponse($response), true);

        $this->assertTrue($response->isClientError());

        $this->assertTrue($response->headers->has('www-authenticate'));

        $this->assertEquals('Missing client_id parameter.', $content['error']['message']);
        $this->assertEquals('OAuthInvalidRequestException', $content['error']['type']);
        $this->assertEquals(400, $content['error']['code']);
    }

    public function testTokenWithoutGrantType()
    {
        $client = $this->createClient();
        $client->request('POST', '/oauth/token', [
            'client_id' => 'foo'
        ]);

        $response = $client->getResponse();
        $content = json_decode($this->parseResponse($response), true);

        $this->assertTrue($response->isClientError());

        $this->assertTrue($response->headers->has('www-authenticate'));

        $this->assertEquals('Missing grant_type parameter.', $content['error']['message']);
        $this->assertEquals('OAuthInvalidRequestException', $content['error']['type']);
        $this->assertEquals(400, $content['error']['code']);
    }

    public function testTokenWithClientNotFound()
    {
        $clientProviderMock = $this->getMock('Euskadi31\Component\Security\Storage\ClientProviderInterface');

        $clientProviderMock->method('get')
            ->will($this->returnValue(null));

        $this->app['oauth2.client.provider'] = function() use ($clientProviderMock) {
            return $clientProviderMock;
        };

        $client = $this->createClient();
        $client->request('POST', '/oauth/token', [
            'client_id' => 'foo',
            'grant_type' => 'password'
        ]);

        $response = $client->getResponse();
        $content = json_decode($this->parseResponse($response), true);

        $this->assertTrue($response->isClientError());

        $this->assertTrue($response->headers->has('www-authenticate'));

        $this->assertEquals('Unknown client', $content['error']['message']);
        $this->assertEquals('OAuthInvalidClientException', $content['error']['type']);
        $this->assertEquals(401, $content['error']['code']);
    }

    public function testTokenWithClientAndBadSecret()
    {
        $client = $this->createClient();
        $client->request('POST', '/oauth/token', [
            'client_id' => 'foo',
            'client_secret' => 'bar1',
            'grant_type' => 'password'
        ]);

        $response = $client->getResponse();
        $content = json_decode($this->parseResponse($response), true);

        $this->assertTrue($response->isClientError());

        $this->assertTrue($response->headers->has('www-authenticate'));

        $this->assertEquals('The authenticated client is not authorized to use this authorization grant type.', $content['error']['message']);
        $this->assertEquals('OAuthUnauthorizedClientException', $content['error']['type']);
        $this->assertEquals(401, $content['error']['code']);
    }

    public function testTokenWithClientUnauthorized()
    {
        $grantTypeCollectionMock    = $this->getMock('Euskadi31\Component\Security\GrantType\GrantTypeCollection');

        $passwordGrantTypeMock      = $this->getMockBuilder('Euskadi31\Component\Security\GrantType\PasswordGrantType')
            ->disableOriginalConstructor()
            ->getMock();

        $passwordGrantTypeMock->method('getName')
            ->will($this->returnValue('password1'));


        $grantTypeCollectionMock->method('get')
            ->will($this->returnValue($passwordGrantTypeMock));

        $this->app['oauth2.grant_types'] = function() use ($grantTypeCollectionMock) {
            return $grantTypeCollectionMock;
        };

        $client = $this->createClient();
        $client->request('POST', '/oauth/token', [
            'client_id' => 'foo',
            'client_secret' => 'bar',
            'grant_type' => 'password1'
        ]);

        $response = $client->getResponse();
        $content = json_decode($this->parseResponse($response), true);

        $this->assertTrue($response->isClientError());

        $this->assertTrue($response->headers->has('www-authenticate'));

        $this->assertEquals('The authenticated client is not authorized to use this authorization grant type.', $content['error']['message']);
        $this->assertEquals('OAuthUnauthorizedClientException', $content['error']['type']);
        $this->assertEquals(401, $content['error']['code']);
    }

    public function testToken()
    {
        $client = $this->createClient();
        $client->request('POST', '/oauth/token', [
            'client_id' => 'foo',
            'grant_type' => 'password'
        ]);

        $response = $client->getResponse();

        $content = json_decode($response->getContent(), true);

        $this->assertTrue($response->isOk());

        $this->assertEquals('foo', $content['access_token']);
        $this->assertEquals('bearer', $content['token_type']);
        $this->assertEquals(0, $content['expires_in']);
    }
}
