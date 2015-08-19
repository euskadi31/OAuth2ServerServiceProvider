<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * @namespace
 */
namespace Euskadi31\Component\Security\Http\Firewall;

use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken;
use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Psr\Log\LoggerInterface;
use Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException;

/**
 * OAuth2 Authentication Listener
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuth2AuthenticationListener implements ListenerInterface
{
    /**
     * @var \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var \Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface
     */
    private $authenticationManager;

    /**
     * @var Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var string
     */
    private $realmName;

    /**
     * @param TokenStorageInterface          $tokenStorage          A TokenStorageInterface instance
     * @param AuthenticationManagerInterface $authenticationManager An AuthenticationManagerInterface instance
     * @param string                         $realmName
     * @param LoggerInterface                $logger
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        $realmName,
        LoggerInterface $logger = null
    )
    {
        $this->tokenStorage             = $tokenStorage;
        $this->authenticationManager    = $authenticationManager;
        $this->logger                   = $logger;
        $this->realmName                = $realmName;
    }

    /**
     * Handle Access Token
     *
     * @param  Request $request
     * @return OAuth2AccessToken
     */
    protected function handleAccessToken(Request $request)
    {
        $accessToken = null;

        $header = $request->headers->get('authorization');

        if (!empty($header)) {
            $pos = strpos($header, 'Bearer');

            if ($pos !== false) {
                $accessToken = substr($header, $pos + 7);
            }
        }

        if (empty($accessToken) && $request->query->has('access_token')) {
            $accessToken = $request->query->get('access_token');
        }

        if (
            empty($accessToken) &&
            $request->getMethod() == 'POST' &&
            $request->server->get('content_type') == 'application/x-www-form-urlencoded'
        ) {
            $accessToken = $request->request->get('access_token');
        }

        if (empty($accessToken)) {
            return null;
        }

        if (null !== $this->logger) {
            $this->logger->info('OAuth2 authentication Authorization header found for user.');
        }

        $token = new OAuth2AccessToken();
        $token->setAccessToken($accessToken);

        return $token;
    }

    /**
     * Handle Client Id
     *
     * @param  Request $request
     * @return OAuth2ClientToken
     */
    protected function handleClientId(Request $request)
    {
        $header = $request->headers->get('authorization');
        $clientId = null;

        if (!empty($header)) {
            $pos = strpos($header, 'Basic');

            if ($pos >= 0) {
                $clientId = explode(':', base64_decode(substr($header, $pos + 6)))[0];
            }
        }

        if (empty($clientId)) {
            $clientId = $request->server->get(
                'PHP_AUTH_USER',
                $request->request->get(
                    'client_id',
                    $request->query->get('client_id')
                )
            );
        }

        if (empty($clientId)) {
            return null;
        }

        if (null !== $this->logger) {
            $this->logger->info('OAuth2 authentication parameter found for client.');
        }

        $token = new OAuth2ClientToken();
        $token->setClientId($clientId);

        return $token;
    }

    /**
     * Handles OAuth2 authentication.
     *
     * @param GetResponseEvent $event A GetResponseEvent instance
     * @throws OAuthExceptionInterface
     * @return void
     */
    final public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $token = $this->handleAccessToken($request);

        if (empty($token)) {
            $token = $this->handleClientId($request);
        }

        if (empty($token)) {
            throw new OAuthInvalidRequestException(
                'Missing client_id or access_token URL parameter.',
                400,
                null,
                $this->realmName
            );
        }

        $token = $this->authenticationManager->authenticate($token);

        return $this->tokenStorage->setToken($token);
    }
}
