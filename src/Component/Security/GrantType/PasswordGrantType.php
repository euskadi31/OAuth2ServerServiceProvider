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
 * PasswordGrantType
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class PasswordGrantType implements GrantTypeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'password';
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Request $request)
    {
        return new Response('grant_type=password');
    }
}
