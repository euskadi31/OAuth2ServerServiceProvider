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
 * ScopeInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface ScopeInterface
{
    /**
     * Get scope identifier
     *
     * @return string
     */
    public function getScope();

    /**
     * Get scope description
     *
     * @return string
     */
    public function getDescription();
}
