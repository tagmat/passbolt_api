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

namespace App\Test\TestCase\Service\JwtAuthentication;

use App\Service\JwtAuthentication\GetJwksPublicService;
use App\Service\JwtAuthentication\GetJwtUserTokenSecretService;
use App\Utility\UuidFactory;
use Cake\Core\Configure;
use Cake\TestSuite\TestCase;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;

/**
 * @covers \App\Service\JwtAuthentication\GetJwtUserTokenSecretService
 */
class GetJwtUserTokenSecretServiceTest extends TestCase
{
    public function tokenExpiration(): array
    {
        return [
            [5, true],
            [0, false],
        ];
    }

    /**
     * @dataProvider tokenExpiration
     */
    public function testGetJwtUserTokenSecretServiceValid(int $expiration, bool $isValid)
    {
        Configure::write('passbolt.auth.token.jwt.expiry', $expiration);
        $userId = UuidFactory::uuid();
        $secretToken = (new GetJwtUserTokenSecretService())->getUserToken($userId);
        $publicKey = file_get_contents((new GetJwksPublicService())->getKeyPath());

        if (!$isValid) {
            $this->expectException(ExpiredException::class);
        }

        $res = JWT::decode($secretToken, $publicKey, array_keys(JWT::$supported_algs));

        if ($isValid) {
            $this->assertSame($userId, $res->sub);
        }
    }
}
