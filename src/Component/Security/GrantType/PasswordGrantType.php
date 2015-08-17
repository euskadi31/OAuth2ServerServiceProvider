<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\GrantType;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Euskadi31\Component\Security\Storage\AccessTokenProviderInterface;
use Euskadi31\Component\Security\Storage\ClientInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;

/**
 * PasswordGrantType
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 * @see https://tools.ietf.org/html/rfc6749#section-4.3
 */
class PasswordGrantType implements GrantTypeInterface
{
    protected $userProvider;

    protected $providerKey;

    protected $accessTokenProvider;

    protected $encoderFactory;

    /**
     *
     * @param UserProviderInterface        $userProvider
     * @param string                       $providerKey
     * @param AccessTokenProviderInterface $accessTokenProvider
     * @param EncoderFactoryInterface      $encoderFactory
     */
    public function __construct(UserProviderInterface $userProvider, $providerKey, AccessTokenProviderInterface $accessTokenProvider, EncoderFactoryInterface $encoderFactory)
    {
        $this->userProvider         = $userProvider;
        $this->providerKey          = $providerKey;
        $this->accessTokenProvider  = $accessTokenProvider;
        $this->encoderFactory       = $encoderFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'password';
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $request, ClientInterface $client)
    {
        $username   = $request->request->get('username');
        $password   = $request->request->get('password');
        $scope      = $request->request->get('scope');

        if (empty($username)) {
            throw new OAuthInvalidRequestException('Missing username parameter.');
        }

        if (empty($password)) {
            throw new OAuthInvalidRequestException('Missing password parameter.');
        }

        $user = $this->userProvider->loadUserByUsername($username);

        $token = new UsernamePasswordToken($username, $password, $this->providerKey);

        if (!$this->encoderFactory->getEncoder($user)->isPasswordValid($user->getPassword(), $token->getCredentials(), $user->getSalt())) {
            throw new OAuthInvalidRequestException('Bad credentials.');
        }

        $accessToken = $this->accessTokenProvider->create($user, $client, $scope);

        $data = [
            'access_token'  => $accessToken->getId(),
            'token_type'    => 'bearer',
            'expires_in'    => $accessToken->getExpires()
        ];

        return new Response(json_encode($data), 200, [
            'Content-Type'  => 'application/json;charset=UTF-8',
            'Cache-Control' => 'no-store',
            'Pragma'        => 'no-cache'
        ]);
    }
}
