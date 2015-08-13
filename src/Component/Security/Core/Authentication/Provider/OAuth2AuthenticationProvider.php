<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Core\Authentication\Provider;


use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Euskadi31\Component\Security\Storage\AccessTokenProviderInterface;
use Euskadi31\Component\Security\Storage\ClientProviderInterface;
use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenExpiredException;
use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException;
//use Euskadi31\Component\Security\Core\Exception\OAuthPermissionsException;
use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2Token;
use Symfony\Component\Security\Core\Exception\AccountStatusException;

/**
 * OAuth2 Authentication Provider
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuth2AuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var \Symfony\Component\Security\Core\User\UserProviderInterface
     */
    protected $userProvider;

    /**
     * @var \Symfony\Component\Security\Core\User\UserChecker
     */
    protected $userChecker;

    /**
     * @var \Euskadi31\Component\Security\Storage\AccessTokenProviderInterface
     */
    protected $accessTokenProvider;

    /**
     * @var \Euskadi31\Component\Security\Storage\ClientProviderInterface
     */
    protected $clientProvider;

    /**
     * @var string
     */
    private $realmName;

    /**
     * @param UserProviderInterface        $userProvider        The user provider.
     * @param UserCheckerInterface         $userChecker
     * @param AccessTokenProviderInterface $accessTokenProvider
     * @param ClientProviderInterface      $clientProvider
     * @param string                       $realmName
     */
    public function __construct(
        UserProviderInterface $userProvider,
        UserCheckerInterface $userChecker,
        AccessTokenProviderInterface $accessTokenProvider,
        ClientProviderInterface $clientProvider,
        $realmName
    )
    {
        $this->userProvider         = $userProvider;
        $this->userChecker          = $userChecker;
        $this->accessTokenProvider  = $accessTokenProvider;
        $this->clientProvider       = $clientProvider;
        $this->realmName            = $realmName;
    }

    /**
     * Check access token
     *
     * @param  AccessTokenInterface $accessToken
     * @return void
     * @throws OAuthAccessTokenNotFoundException
     * @throws OAuthAccessTokenExpiredException
     */
    protected function checkAccessToken($accessToken)
    {
        if (empty($accessToken)) {
            throw new OAuthAccessTokenNotFoundException(
                'The access token could not be found.',
                401,
                null,
                $this->realmName
            );
        }

        if ($accessToken->isExpired()) {
            throw new OAuthAccessTokenExpiredException(
                'The access token provided has expired.',
                401,
                null,
                $this->realmName
            );
        }

        if ($accessToken->isRevoked()) {
            throw new OAuthAccessTokenExpiredException(
                'The access token provided was revoked.',
                401,
                null,
                $this->realmName
            );
        }
    }

    /**
     * Check client
     *
     * @param  ClientInterface|null $client
     * @return void
     * @throws OAuthAccessTokenNotFoundException
     */
    protected function checkClient($client)
    {
        if (empty($client) || !$client->isEnabled() || $client->isLocked()) {
            throw new OAuthAccessTokenNotFoundException(
                'The access token could not be found.',
                401,
                null,
                $this->realmName
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        $accessToken = $this->accessTokenProvider->get($token->getAccessToken());

        $this->checkAccessToken($accessToken);

        $client = $this->clientProvider->get($accessToken->getClient());

        $this->checkClient($client);

        // check scope

        $user = $this->userProvider->loadUserByUsername($accessToken->getUsername());

        try {
            $this->userChecker->checkPreAuth($user);
        } catch (AccountStatusException $e) {
            throw new OAuthAccessTokenNotFoundException(
                $e->getMessage(),
                401,
                $e,
                $this->realmName
            );
        }

        $token = new OAuth2Token($user->getRoles());
        $token->setAuthenticated(true);
        $token->setAccessToken($accessToken->getId());
        $token->setUser($user);
        $token->setClient($client);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuth2Token;
    }
}
