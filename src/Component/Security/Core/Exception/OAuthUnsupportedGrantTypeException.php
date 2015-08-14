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
 * OAuthUnsupportedGrantTypeException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthUnsupportedGrantTypeException extends InvalidArgumentException implements OAuthExceptionInterface, HttpExceptionInterface
{
    use OAuthExceptionTrait;

    /**
     *
     * @param string         $message
     * @param integer        $code
     * @param Exception|null $previous
     * @param string         $realmName
     */
    public function __construct($message = '', $code = 400, Exception $previous = null, $realmName = 'API')
    {
        if (empty($message)) {
            $message = 'The authorization grant type is not supported by the authorization server.';
        }

        parent::__construct($message, $code, $previous);

        $this->statusCode   = $code;
        $this->errorCode    = 'unsupported_grant_type';
        $this->realmName    = $realmName;
    }
}
