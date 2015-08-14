<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\GrantType;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * AuthorizationCodeGrantType
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class AuthorizationCodeGrantType implements GrantTypeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'authorization_code';
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $request)
    {
        return new Response();
    }
}
