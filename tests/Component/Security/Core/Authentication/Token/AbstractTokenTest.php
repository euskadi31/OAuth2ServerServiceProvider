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

use Euskadi31\Component\Security\Core\Authentication\Token\AbstractToken;

class AbstractTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testToken()
    {
        $client = $this->getMock('Euskadi31\Component\Security\Storage\ClientInterface');

        $token = new TestAbstractToken();
        $token->setClient($client);

        $this->assertEquals($client, $token->getClient());
    }
}

class TestAbstractToken extends AbstractToken
{
    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return;
    }
}
