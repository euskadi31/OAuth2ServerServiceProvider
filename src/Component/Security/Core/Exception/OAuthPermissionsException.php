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

use Symfony\Component\Security\Core\Exception\InsufficientAuthenticationException;

/**
 * OAuthPermissionsException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthPermissionsException extends InsufficientAuthenticationException
{
    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'The request requires higher privileges than provided by the access token.';
    }
}
