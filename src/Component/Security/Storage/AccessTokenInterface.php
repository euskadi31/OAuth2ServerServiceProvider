

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
 * AccessTokenInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface AccessTokenInterface
{
    /**
     * Get username of owner
     *
     * @return string
     */
    public function getUsername()

    /**
     * Get scopes
     *
     * @return array
     */
    public function getScopes();

    /**
     * Get expires
     *
     * @return integer
     */
    public function getExpires();
}
