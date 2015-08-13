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
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * OAuthInvalidAccessTokenException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthInvalidAccessTokenException extends InvalidArgumentException implements OAuthExceptionInterface, HttpExceptionInterface
{
    use OAuthExceptionTrait;

    /**
     *
     * @param string         $message
     * @param integer        $code
     * @param Exception|null $previous
     */
    public function __construct($message = '', $code = 401, Exception $previous = null, $realmName = 'API')
    {
        parent::__construct($message, $code, $previous);

        $this->statusCode   = $code;
        $this->errorCode    = 'invalid_token';
        $this->realmName    = $realmName;
    }
}
