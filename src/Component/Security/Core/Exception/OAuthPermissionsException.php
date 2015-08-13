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

use Symfony\Component\Security\Core\Exception\InsufficientAuthenticationException;
use Exception;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * OAuthPermissionsException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthPermissionsException extends InsufficientAuthenticationException implements OAuthExceptionInterface, HttpExceptionInterface
{
    use OAuthExceptionTrait;

    /**
     *
     * @param string         $message
     * @param integer        $code
     * @param Exception|null $previous
     * @param array          $scope
     */
    public function __construct($message = '', $code = 403, Exception $previous = null, $scope = [], $realmName = 'API')
    {
        parent::__construct($message, $code, $previous);

        $this->scopes       = $scopes;
        $this->statusCode   = $code;
        $this->errorCode    = 'insufficient_scope';
        $this->realmName    = $realmName;
    }

    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'The request requires higher privileges than provided by the access token.';
    }
}
