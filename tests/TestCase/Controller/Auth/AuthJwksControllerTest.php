<?php
declare(strict_types=1);

/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         3.3.0
 */
namespace App\Test\TestCase\Controller\Auth;

use App\Test\Lib\Utility\JsonRequestTrait;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;

class AuthJwksControllerTest extends TestCase
{
    use IntegrationTestTrait;
    use JsonRequestTrait;

    public function testAuthJwksControllerRsaSuccess()
    {
        $this->getJson('/auth/jwt/rsa.json');
        $this->assertResponseOk();
        $responseKeys = $this->_responseJsonBody->keydata;
        $this->assertTextContains('-----BEGIN PUBLIC KEY-----', $responseKeys);
    }

    public function testAuthJwksControllerJwksSuccess()
    {
        $this->get('/auth/jwt/jwks.json');
        $this->_responseJsonBody = json_decode($this->_getBodyAsString());
        $this->assertResponseOk();
        $this->assertCount(1, $this->_responseJsonBody->keys);
        $responseKey = $this->_responseJsonBody->keys[0];
        $this->assertSame('RSA', $responseKey->kty);
        $this->assertSame('RS256', $responseKey->alg);
    }

    public function testAuthJwksControllerJwksRedirect()
    {
        $this->get('/.well-known/jwks.json');
        $this->assertResponseCode(301);
    }
}
