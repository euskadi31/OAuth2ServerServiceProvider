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

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken as BaseToken;
use Euskadi31\Component\Security\Storage\ClientInterface;

/**
 * OAuth2 abstract token
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
abstract class AbstractToken extends BaseToken
{
    /**
     * @var ClientInterface
     */
    protected $client;

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
}
