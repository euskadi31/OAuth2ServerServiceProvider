<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Core\Exception;

/**
 * OAuthExceptionInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface OAuthExceptionInterface
{
    /**
     * Get error code
     *
     * @return string
     */
    public function getErrorCode();

    /**
     * Get scope
     *
     * @return array
     */
    public function getScopes();
}
