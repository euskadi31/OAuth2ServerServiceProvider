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
use Euskadi31\Component\Security\Storage\ClientInterface;

/**
 * GrantTypeInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface GrantTypeInterface
{
    /**
     * Get name of grant_type
     *
     * @return string
     */
    public function getName();

    /**
     * Handle request
     *
     * @param  Request         $request
     * @param  ClientInterface $client
     * @return Response
     */
    public function handle(Request $request, ClientInterface $client);
}
