<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Core\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Euskadi31\Component\Security\Storage\ClientInterface;

/**
 * OAuth2 token
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuth2Token extends AbstractToken
{
    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var ClientInterface
     */
    protected $client;

    /**
     * Set access token
     *
     * @param string $token
     */
    public function setAccessToken($token)
    {
        $this->accessToken = $token;
    }

    /**
     * Get access token
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Set client
     *
     * @param ClientInterface $client
     */
    public function setClient(ClientInterface $client)
    {
        $this->client = $client;
    }

    /**
     * Get client
     *
     * @return ClientInterface
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return $this->accessToken;
    }
}
