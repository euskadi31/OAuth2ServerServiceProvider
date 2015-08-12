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
 * AuthCodeInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface AuthCodeInterface
{
    /**
     * Get the auth code
     *
     * @return string
     */
    public function getAuthCode();

    /**
     * Get the redirect URI
     *
     * @return string
     */
    public function getRedirectUri();
}
