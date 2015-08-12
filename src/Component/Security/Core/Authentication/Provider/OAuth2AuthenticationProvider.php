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
use Euskadi31\Component\Security\Http\OAuth2\Provider\UserProviderInterface;
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
     * @param UserProviderInterface        $userProvider        The user provider.
     * @param UserCheckerInterface         $userChecker
     * @param AccessTokenProviderInterface $accessTokenProvider
     */
    public function __construct(
        UserProviderInterface $userProvider,
        UserCheckerInterface $userChecker,
        AccessTokenProviderInterface $accessTokenProvider
    )
    {
        $this->userProvider         = $userProvider;
        $this->userChecker          = $userChecker;
        $this->accessTokenProvider  = $accessTokenProvider;
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
            throw new OAuthAccessTokenNotFoundException('Error validating verification code.', 400);
        }

        if ($accessToken->getExpires() != 0 && $accessToken->getExpires() < time()) {
            throw new OAuthAccessTokenExpiredException('The access token provided has expired.', 401);
        }

        // check scope

        $user = $this->userProvider->loadUserByUsername($accessToken->getUsername());

        $token = new OAuth2Token($user->getRoles());
        $token->setAuthenticated(true);
        $token->setAccessToken($accessToken->get());
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
