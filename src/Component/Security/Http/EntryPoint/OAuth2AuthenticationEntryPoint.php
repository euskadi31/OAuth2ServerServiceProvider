<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * @namespace
 */
namespace Euskadi31\Component\Security\Http\EntryPoint;

use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Psr\Log\LoggerInterface;
use Euskadi31\Component\Security\Core\Exception\OAuthExceptionInterface;

/**
 * OAuth2AuthenticationEntryPoint starts an OAuth2 authentication.
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuth2AuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * @var string
     */
    private $realmName;

    /**
     * @var LoggerInterface|null
     */
    private $logger;

    /**
     *
     * @param string               $realmName
     * @param LoggerInterface|null $logger
     */
    public function __construct($realmName, LoggerInterface $logger = null)
    {
        $this->realmName    = $realmName;
        $this->logger       = $logger;
    }

    /**
     *
     * @param  string $str
     * @return string
     */
    protected function quotedString($str)
    {
        $str = preg_replace('~
          [^
            \x21-\x7E
            \x80-\xFF
            \ \t
          ]
          ~x', '', $str);

        $str = addcslashes($str, '"\\');

        return '"' . $str . '"';
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $authenticateHeader = sprintf('Bearer realm=%s', $this->quotedString($this->realmName));

        if ($authException instanceof OAuthExceptionInterface) {
            $authenticateHeader .= sprintf(', error="%s"', $authException->getErrorCode());
            $authenticateHeader .= sprintf(', error_description=%s', $this->quotedString($authException->getMessage()));
        }

        if (null !== $this->logger) {
            $this->logger->debug('WWW-Authenticate header sent.', ['header' => $authenticateHeader]);
        }

        $response = new Response();
        $response->headers->set('WWW-Authenticate', $authenticateHeader);
        $response->setStatusCode(401);

        return $response;
    }
}
