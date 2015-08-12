<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Storage;

/**
 * ClientProviderInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface ClientProviderInterface
{
    /**
     * Get the client by id and secret
     *
     * @param string $id
     * @param string $secret
     * @return ClientInterface
     */
    public function get($id, $secret = null);
}
