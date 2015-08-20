<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Http\Firewall;

use Euskadi31\Component\Security\Http\Firewall\OAuth2AuthenticationListener;
use Symfony\Component\HttpFoundation\HeaderBag;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\ServerBag;

class OAuth2AuthenticationListenerTest extends \PHPUnit_Framework_TestCase
{
    public function testAuthenticationByAccessTokenInHeader()
    {
        $tokenStorageMock   = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authManagerMock    = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $authManagerMock->expects($this->once())
            ->method('authenticate')
            ->with($this->callback(function($arg) {
                if (!$arg instanceof \Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken) {
                    return false;
                }

                if ($arg->getSignedUrl() != 'https://api.domain.info/v1/me?access_token=foo') {
                    return false;
                }

                return true;
            }));
        $loggerMock         = $this->getMock('Psr\Log\LoggerInterface');

        $listener = new OAuth2AuthenticationListener($tokenStorageMock, $authManagerMock, 'Foo', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $requestMock->headers = new HeaderBag;
        $requestMock->query = new ParameterBag;
        $requestMock->server = new ServerBag;
        $requestMock->request = new ParameterBag;
        $requestMock->headers->set('authorization', 'Bearer foo');
        $requestMock->method('getUri')
            ->will($this->returnValue('https://api.domain.info/v1/me?access_token=foo'));

        $getResponseEventMock = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->getMock();
        $getResponseEventMock->method('getRequest')
            ->will($this->returnValue($requestMock));

        $listener->handle($getResponseEventMock);
    }

    public function testAuthenticationByAccessTokenInQuery()
    {
        $tokenStorageMock   = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authManagerMock    = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $authManagerMock->expects($this->once())
            ->method('authenticate')
            ->with($this->callback(function($arg) {
                if (!$arg instanceof \Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken) {
                    return false;
                }

                if ($arg->getSignedUrl() != 'https://api.domain.info/v1/me?access_token=foo') {
                    return false;
                }

                return true;
            }));
        $loggerMock         = $this->getMock('Psr\Log\LoggerInterface');

        $listener = new OAuth2AuthenticationListener($tokenStorageMock, $authManagerMock, 'Foo', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $requestMock->headers = new HeaderBag;
        $requestMock->query = new ParameterBag;
        $requestMock->server = new ServerBag;
        $requestMock->request = new ParameterBag;
        $requestMock->query->set('access_token', 'foo');
        $requestMock->method('getUri')
            ->will($this->returnValue('https://api.domain.info/v1/me?access_token=foo'));

        $getResponseEventMock = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->getMock();
        $getResponseEventMock->method('getRequest')
            ->will($this->returnValue($requestMock));

        $listener->handle($getResponseEventMock);
    }

    public function testAuthenticationByAccessTokenInBody()
    {
        $tokenStorageMock   = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authManagerMock    = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $authManagerMock->expects($this->once())
            ->method('authenticate')
            ->with($this->callback(function($arg) {
                if (!$arg instanceof \Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken) {
                    return false;
                }

                if ($arg->getSignedUrl() != 'https://api.domain.info/v1/me?access_token=foo') {
                    return false;
                }

                return true;
            }));
        $loggerMock         = $this->getMock('Psr\Log\LoggerInterface');

        $listener = new OAuth2AuthenticationListener($tokenStorageMock, $authManagerMock, 'Foo', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $requestMock->headers = new HeaderBag;
        $requestMock->query = new ParameterBag;
        $requestMock->server = new ServerBag;
        $requestMock->server->set('content_type', 'application/x-www-form-urlencoded');
        $requestMock->request = new ParameterBag;
        $requestMock->request->set('access_token', 'foo');
        $requestMock->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue('POST'));
        $requestMock->method('getUri')
            ->will($this->returnValue('https://api.domain.info/v1/me?access_token=foo'));

        $getResponseEventMock = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->getMock();
        $getResponseEventMock->method('getRequest')
            ->will($this->returnValue($requestMock));

        $listener->handle($getResponseEventMock);
    }

    public function testAuthenticationByClientIdInHeader()
    {
        $tokenStorageMock   = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authManagerMock    = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $authManagerMock->expects($this->once())
            ->method('authenticate')
            ->with($this->callback(function($arg) {
                if (!$arg instanceof \Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken) {
                    return false;
                }

                if ($arg->getSignedUrl() != 'https://api.domain.info/v1/me?access_token=foo') {
                    return false;
                }

                return true;
            }));
        $loggerMock         = $this->getMock('Psr\Log\LoggerInterface');

        $listener = new OAuth2AuthenticationListener($tokenStorageMock, $authManagerMock, 'Foo', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $requestMock->headers = new HeaderBag;
        $requestMock->headers->set('Authorization', sprintf('Basic %s', base64_encode('foo')));
        $requestMock->query = new ParameterBag;
        $requestMock->server = new ServerBag;
        $requestMock->server->set('content_type', 'application/x-www-form-urlencoded');
        $requestMock->request = new ParameterBag;
        $requestMock->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue('POST'));
        $requestMock->method('getUri')
            ->will($this->returnValue('https://api.domain.info/v1/me?access_token=foo'));

        $getResponseEventMock = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->getMock();
        $getResponseEventMock->method('getRequest')
            ->will($this->returnValue($requestMock));

        $listener->handle($getResponseEventMock);
    }

     public function testAuthenticationByClientIdAndClientSecretInHeader()
    {
        $tokenStorageMock   = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authManagerMock    = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $authManagerMock->expects($this->once())
            ->method('authenticate')
            ->with($this->callback(function($arg) {
                if (!$arg instanceof \Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken) {
                    return false;
                }

                if ($arg->getSignedUrl() != 'https://api.domain.info/v1/me?access_token=foo') {
                    return false;
                }

                return true;
            }));
        $loggerMock         = $this->getMock('Psr\Log\LoggerInterface');

        $listener = new OAuth2AuthenticationListener($tokenStorageMock, $authManagerMock, 'Foo', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $requestMock->headers = new HeaderBag;
        $requestMock->headers->set('Authorization', sprintf('Basic %s', base64_encode('foo:bar')));
        $requestMock->query = new ParameterBag;
        $requestMock->server = new ServerBag;
        $requestMock->server->set('content_type', 'application/x-www-form-urlencoded');
        $requestMock->request = new ParameterBag;
        $requestMock->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue('POST'));
        $requestMock->method('getUri')
            ->will($this->returnValue('https://api.domain.info/v1/me?access_token=foo'));

        $getResponseEventMock = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->getMock();
        $getResponseEventMock->method('getRequest')
            ->will($this->returnValue($requestMock));

        $listener->handle($getResponseEventMock);
    }

    public function testAuthenticationByClientId()
    {
        $tokenStorageMock   = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authManagerMock    = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $authManagerMock->expects($this->once())
            ->method('authenticate')
            ->with($this->callback(function($arg) {
                if (!$arg instanceof \Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken) {
                    return false;
                }

                if ($arg->getSignedUrl() != 'https://api.domain.info/v1/me?access_token=foo') {
                    return false;
                }

                return true;
            }));
        $loggerMock         = $this->getMock('Psr\Log\LoggerInterface');

        $listener = new OAuth2AuthenticationListener($tokenStorageMock, $authManagerMock, 'Foo', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $requestMock->headers = new HeaderBag;
        $requestMock->query = new ParameterBag;
        $requestMock->query->set('client_id', 'foo');
        $requestMock->server = new ServerBag;
        $requestMock->server->set('content_type', 'application/x-www-form-urlencoded');
        $requestMock->request = new ParameterBag;
        $requestMock->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue('POST'));
        $requestMock->method('getUri')
            ->will($this->returnValue('https://api.domain.info/v1/me?access_token=foo'));

        $getResponseEventMock = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->getMock();
        $getResponseEventMock->method('getRequest')
            ->will($this->returnValue($requestMock));

        $listener->handle($getResponseEventMock);
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException
     * @expectedExceptionMessage Missing client_id or access_token URL parameter.
     */
    public function testAuthenticationWithBadRequest()
    {
        $tokenStorageMock   = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        $authManagerMock    = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $authManagerMock->expects($this->exactly(0))
            ->method('authenticate');
        $loggerMock         = $this->getMock('Psr\Log\LoggerInterface');

        $listener = new OAuth2AuthenticationListener($tokenStorageMock, $authManagerMock, 'Foo', $loggerMock);

        $requestMock = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $requestMock->headers = new HeaderBag;
        $requestMock->query = new ParameterBag;
        $requestMock->server = new ServerBag;
        $requestMock->server->set('content_type', 'application/x-www-form-urlencoded');
        $requestMock->request = new ParameterBag;
        $requestMock->expects($this->once())
            ->method('getMethod')
            ->will($this->returnValue('POST'));

        $getResponseEventMock = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->getMock();
        $getResponseEventMock->method('getRequest')
            ->will($this->returnValue($requestMock));

        $listener->handle($getResponseEventMock);
    }
}
