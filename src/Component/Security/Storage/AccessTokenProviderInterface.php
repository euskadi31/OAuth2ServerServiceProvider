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

use Symfony\Component\Security\Core\User\UserInterface;

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
     */
    public function get($accessToken);

    /**
     * Create access token
     *
     * @param  UserInterface   $user
     * @param  ClientInterface $client
     * @param  array|null      $scope
     * @return AccessTokenInterface
     */
    public function create(UserInterface $user, ClientInterface $client, $scope = null);
}
