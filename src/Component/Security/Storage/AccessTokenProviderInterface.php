

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
 * AccessTokenProviderInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface AccessTokenProviderInterface
{
    /**
     * Get AccessToken by AccessToken
     *
     * @param  string $accessToken
     * @return AccessTokenInterface
     * @throws Euskadi31\Component\Security\Core\Exception\OAuthException
     */
    public function get($accessToken);
}
