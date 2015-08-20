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


use Euskadi31\Component\Security\Core\Authentication\Token\AbstractToken;
use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2AccessToken;
use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken;
use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenExpiredException;
use Euskadi31\Component\Security\Core\Exception\OAuthAccessTokenNotFoundException;
use Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException;
use Euskadi31\Component\Security\Http\Signature\SignatureInterface;
use Euskadi31\Component\Security\Storage\AccessTokenProviderInterface;
use Euskadi31\Component\Security\Storage\ClientInterface;
use Euskadi31\Component\Security\Storage\ClientProviderInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

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
     * @var \Euskadi31\Component\Security\Http\Signature\SignatureInterface
     */
    protected $signature;

    /**
     * @var string
     */
    private $realmName;

    /**
     * @param UserProviderInterface        $userProvider        The user provider.
     * @param UserCheckerInterface         $userChecker
     * @param AccessTokenProviderInterface $accessTokenProvider
     * @param ClientProviderInterface      $clientProvider
     * @param SignatureInterface           $signature
     * @param string                       $realmName
     */
    public function __construct(
        UserProviderInterface $userProvider,
        UserCheckerInterface $userChecker,
        AccessTokenProviderInterface $accessTokenProvider,
        ClientProviderInterface $clientProvider,
        SignatureInterface $signature,
        $realmName
    )
    {
        $this->userProvider         = $userProvider;
        $this->userChecker          = $userChecker;
        $this->accessTokenProvider  = $accessTokenProvider;
        $this->clientProvider       = $clientProvider;
        $this->signature            = $signature;
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
     * Check signature
     *
     * @param  TokenInterface  $token
     * @param  ClientInterface $client
     * @return void
     */
    protected function checkSignature(TokenInterface $token, ClientInterface $client)
    {
        if ($client->isSignatureRequired() && !$token->isSigned()) {
            throw new OAuthInvalidRequestException('The request is not signed.');
        }

        if ($client->isSignatureRequired() && $token->isSigned()) {
            if (!$this->signature->verify($token->getSignedUrl(), $client->getSecret(), $token->getSignature())) {
                throw new OAuthInvalidRequestException('The request signature we calculated does not match the signature you provided.');
            }
        }
    }

    /**
     * Authenticate with access token
     *
     * @param  TokenInterface $token
     * @return OAuth2AccessToken
     */
    protected function authenticateAccessToken(TokenInterface $token)
    {
        $accessToken = $this->accessTokenProvider->get($token->getAccessToken());

        $this->checkAccessToken($accessToken);

        $client = $this->clientProvider->get($accessToken->getClient());

        $this->checkClient($client);

        $this->checkSignature($token, $client);

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

        $retval = new OAuth2AccessToken($user->getRoles());
        $retval->setAuthenticated(true);
        $retval->setAccessToken($accessToken->getId());
        $retval->setUser($user);
        $retval->setClient($client);
        $retval->setSignature($token->getSignature());

        return $retval;
    }

    /**
     * Authenticate with client id
     *
     * @param  TokenInterface $token
     * @return OAuth2ClientToken
     */
    protected function authenticateClientId(TokenInterface $token)
    {
        $client = $this->clientProvider->get($token->getClientId());

        $this->checkClient($client);

        $this->checkSignature($token, $client);

        $retval = new OAuth2ClientToken([]);
        $retval->setAuthenticated(true);
        $retval->setClientId($token->getClientId());
        $retval->setClient($client);
        $retval->setSignature($token->getSignature());

        return $retval;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        if ($token instanceof OAuth2AccessToken) {
            $token = $this->authenticateAccessToken($token);
        } else if ($token instanceof OAuth2ClientToken) {
            $token = $this->authenticateClientId($token);
        }

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof AbstractToken;
    }
}
