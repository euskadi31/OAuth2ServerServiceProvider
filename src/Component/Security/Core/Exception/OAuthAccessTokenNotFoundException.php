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

use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;

/**
 * OAuthAccessTokenNotFoundException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthAccessTokenNotFoundException extends AuthenticationCredentialsNotFoundException
{
    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'The access token could not be found.';
    }
}
