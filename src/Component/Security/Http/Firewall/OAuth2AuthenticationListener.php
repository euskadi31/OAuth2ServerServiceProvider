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

use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2Token;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Psr\Log\LoggerInterface;

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
     * @var \Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface
     */
    private $authenticationEntryPoint;

    /**
     * @var Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @param TokenStorageInterface             $tokenStorage             A TokenStorageInterface instance
     * @param AuthenticationManagerInterface    $authenticationManager    An AuthenticationManagerInterface instance
     * @param AuthenticationEntryPointInterface $authenticationEntryPoint
     * @param LoggerInterface                   $logger
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        AuthenticationEntryPointInterface $authenticationEntryPoint,
        LoggerInterface $logger = null
    )
    {
        $this->tokenStorage             = $tokenStorage;
        $this->authenticationManager    = $authenticationManager;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->logger                   = $logger;
    }

    /**
     * Handles OAuth2 authentication.
     *
     * @param GetResponseEvent $event A GetResponseEvent instance
     * @throws \RuntimeException
     * @return void
     */
    final public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $accessToken = null;

        $header = null;

        if (!$request->headers->has('Authorization')) {
            // The Authorization header may not be passed to PHP by Apache;
            // Trying to obtain it through apache_request_headers()
            if (function_exists('apache_request_headers')) {
                $headers = apache_request_headers();

                // Server-side fix for bug in old shitty Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
                $headers = array_combine(
                    array_map(
                        'ucwords',
                        array_keys($headers)
                    ),
                    array_values($headers)
                );

                if (isset($headers['Authorization'])) {
                    $header = $headers['Authorization'];
                }
            }
        } else {
            $header = $request->headers->get('authorization');
        }

        if (!empty($header)) {
            $pos = strpos($header, 'Bearer');

            if ($pos > 0) {
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
            return;
        }

        if (null !== $this->logger) {
            $this->logger->info('OAuth2 authentication Authorization header found for user.');
        }

        $token = new OAuth2Token();
        $token->setAccessToken($accessToken);

        try {
            $token = $this->authenticationManager->authenticate($token);

            return $this->tokenStorage->setToken($token);
        } catch (AuthenticationException $e) {
            if (null !== $this->logger) {
                $this->logger->info('OAuth2 authentication failed for user.', ['exception' => $e]);
            }

            $event->setResponse($this->authenticationEntryPoint->start($request, $e));
        }
    }
}
