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

use ArrayObject;
use Euskadi31\Component\Security\Core\Exception\OAuthUnsupportedGrantTypeException;
use InvalidArgumentException;

/**
 * GrantTypeInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class GrantTypeCollection extends ArrayObject
{
    /**
     * Add grant type
     *
     * @param GrantTypeInterface $grantType
     * @return GrantTypeCollection
     * @throws InvalidArgumentException
     */
    public function addGrantType(GrantTypeInterface $grantType)
    {
        $grantTypeName = strtolower($grantType->getName());

        if ($this->offsetExists($grantTypeName)) {
            throw new InvalidArgumentException(sprintf(
                'Grant Type "%s" already defined.',
                $grantTypeName
            ));
        }

        $this->offsetSet($grantTypeName, $grantType);

        return $this;
    }

    /**
     * Get grant type by name
     *
     * @param  string $grantType
     * @return GrantTypeInterface
     * @throws OAuthUnsupportedGrantTypeException
     */
    public function get($grantType)
    {
        $grantType = strtolower($grantType);

        if ($this->offsetExists($grantType)) {
            return $this->offsetGet($grantType);
        }

        throw new OAuthUnsupportedGrantTypeException();
    }
}
