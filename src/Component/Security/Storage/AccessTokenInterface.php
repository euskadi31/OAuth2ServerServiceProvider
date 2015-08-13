

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
     * Get client id
     *
     * @return string
     */
    public function getClient();

    /**
     * Get user id
     *
     * @return integer
     */
    public function getUser();

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

    /**
     * Check if access_token has expired
     *
     * @return boolean
     */
    public function hasExpired();

    /**
     * Check if access_token is revoked
     *
     * @return boolean
     */
    public function isRevoked();
}
