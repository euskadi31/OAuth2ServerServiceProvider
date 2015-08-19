<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Http\Signature;

/**
 * Signature interface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface SignatureInterface
{
    /**
     * Sign url
     *
     * @param  string $url
     * @param  string $key
     * @return string
     */
    public function sign($url, $key);

    /**
     * Verify signature
     *
     * @param  string $url
     * @param  string $key
     * @param  string $signature
     * @return boolean
     */
    public function verify($url, $key, $signature = null);
}
