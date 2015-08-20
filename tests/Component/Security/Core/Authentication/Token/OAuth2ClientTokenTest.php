<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Core\Authentication\Token;

use Euskadi31\Component\Security\Core\Authentication\Token\OAuth2ClientToken;

class OAuth2ClientTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testToken()
    {
        $token = new OAuth2ClientToken();
        $token->setClientId('foo');
        $token->setClientSecret('bar');

        $this->assertEquals('foo', $token->getClientId());
        $this->assertEquals('bar', $token->getCredentials());
        $this->assertEquals('bar', $token->getClientSecret());
    }
}
