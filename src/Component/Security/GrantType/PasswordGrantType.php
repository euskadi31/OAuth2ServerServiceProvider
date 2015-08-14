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
use Euskadi31\Component\Security\Core\Exception\OAuthInvalidRequestException;

/**
 * PasswordGrantType
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 * @see https://tools.ietf.org/html/rfc6749#section-4.3
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
        $username   = $request->request->get('username');
        $password   = $request->request->get('password');
        $scope      = $request->request->get('scope');

        if (empty($username)) {
            throw new OAuthInvalidRequestException('Missing username parameter.');
        }

        if (empty($password)) {
            throw new OAuthInvalidRequestException('Missing password parameter.');
        }


        return new Response('grant_type=password');
    }
}
