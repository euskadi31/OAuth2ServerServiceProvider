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
use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException;

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
     * @var string
     */
    private $realmName;

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
        $realmName,
        LoggerInterface $logger = null
    )
    {
        $this->tokenStorage             = $tokenStorage;
        $this->authenticationManager    = $authenticationManager;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->logger                   = $logger;
        $this->realmName                = $realmName;
    }

    /**
     * Quoted string for authenticate header
     *
     * @param  string $str
     * @return string
     */
    /*protected function quotedString($str)
    {
        $str = preg_replace('~
          [^
            \x21-\x7E
            \x80-\xFF
            \ \t
          ]
          ~x', '', $str);
        $str = addcslashes($str, '"\\');

        return '"' . $str . '"';
    }*/

    /**
     * get authenticate headers
     *
     * @return array
     */
    /*protected function getAuthenticateHeaders($authException = null)
    {
        $authenticateHeader = sprintf('Bearer realm=%s', $this->quotedString($this->realmName));

        if ($authException instanceof OAuthExceptionInterface) {
            $authenticateHeader .= sprintf(', error=%s', $this->quotedString($authException->getErrorCode()));
            $authenticateHeader .= sprintf(', error_description=%s', $this->quotedString($authException->getMessage()));

            $scopes = $authException->getScopes();

            if (!empty($scopes)) {
                $authenticateHeader .= sprintf(', scope=%s', $this->quotedString(implode(' ', $scopes)));
            }
        }

        if (null !== $this->logger) {
            $this->logger->debug('WWW-Authenticate header sent.', [
                'header' => $authenticateHeader
            ]);
        }

        return [
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => $authenticateHeader
        ];
    }*/

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
            throw new OAuthAccessTokenNotFoundException(
                'An access token is required to request this resource.',
                400,
                null,
                $this->realmName
            );
        }

        if (null !== $this->logger) {
            $this->logger->info('OAuth2 authentication Authorization header found for user.');
        }

        $token = new OAuth2Token();
        $token->setAccessToken($accessToken);

        $token = $this->authenticationManager->authenticate($token);

        return $this->tokenStorage->setToken($token);

        /*try {

        } catch (AuthenticationException $e) {
            if (null !== $this->logger) {
                $this->logger->info('OAuth2 authentication failed for user.', ['exception' => $e]);
            }

            $event->setResponse($this->authenticationEntryPoint->start($request, $e));
        }*/
    }
}
