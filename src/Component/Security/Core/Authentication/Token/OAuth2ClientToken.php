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

/**
 * OAuth2 client token
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuth2ClientToken extends AbstractToken
{
    /**
     * @var string
     */
    protected $clientId;

    /**
     * Set client id
     *
     * @param string $clientId
     */
    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
    }

    /**
     * Get client id
     *
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return $this->clientId;
    }
}
