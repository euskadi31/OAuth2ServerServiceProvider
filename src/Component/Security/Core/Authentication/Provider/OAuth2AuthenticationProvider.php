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
use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenExpiredException;
use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException;
//use Euskadi31\Component\Security\Core\Exception\OAuthPermissionsException;
use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2Token;

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
     * @var string
     */
    private $realmName;

    /**
     * @param UserProviderInterface        $userProvider        The user provider.
     * @param UserCheckerInterface         $userChecker
     * @param AccessTokenProviderInterface $accessTokenProvider
     */
    public function __construct(
        UserProviderInterface $userProvider,
        UserCheckerInterface $userChecker,
        AccessTokenProviderInterface $accessTokenProvider,
        $realmName
    )
    {
        $this->userProvider         = $userProvider;
        $this->userChecker          = $userChecker;
        $this->accessTokenProvider  = $accessTokenProvider;
        $this->realmName            = $realmName;
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

        // check scope

        $user = $this->userProvider->loadUserByUsername($accessToken->getUsername());

        $token = new OAuth2Token($user->getRoles());
        $token->setAuthenticated(true);
        $token->setAccessToken($accessToken->getId());
        $token->setUser($user);

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
