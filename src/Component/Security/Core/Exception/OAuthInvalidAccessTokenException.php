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

use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Exception;

/**
 * OAuthInvalidAccessTokenException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthInvalidAccessTokenException extends InvalidArgumentException implements OAuthExceptionInterface
{
    /**
     *
     * @param string         $message
     * @param integer        $code
     * @param Exception|null $previous
     */
    public function __construct($message = '', $code = 401, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    /**
     * {@inheritdoc}
     */
    public function getErrorCode()
    {
        return 'invalid_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes()
    {
        return [];
    }
}
