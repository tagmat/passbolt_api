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

use App\Model\Entity\AuthenticationToken;
use App\Service\JwtAuthentication\JwtKeyPairCreateService;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\UserFactory;
use App\Test\Lib\AppIntegrationTestCase;
use App\Test\Lib\Utility\JsonRequestTrait;
use Cake\Datasource\ModelAwareTrait;
use Cake\TestSuite\IntegrationTestTrait;

/**
 * Class AuthJwtLogoutControllerTest
 *
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class AuthJwtLogoutControllerTest extends AppIntegrationTestCase
{
    use IntegrationTestTrait;
    use JsonRequestTrait;
    use ModelAwareTrait;

    public function setUp(): void
    {
        parent::setUp();

        $this->loadModel('AuthenticationTokens');
        (new JwtKeyPairCreateService())->createKeyPair();
    }

    public function testAuthRefreshTokenControllerUnauthenticated()
    {
        $this->postJson('/auth/jwt/logout.json');
        $this->assertResponseError();
    }

    public function testAuthJwtLogoutControllerNoPayload()
    {
        $user = UserFactory::make()->user()->persist();
        $this->createJwtTokenAndSetInHeader($user->id);
        $nToken = 3;
        AuthenticationTokenFactory::make($nToken)
            ->active()
            ->type(AuthenticationToken::TYPE_REFRESH_TOKEN)
            ->userId($user->id)
            ->persist();

        $this->postJson('/auth/jwt/logout.json');
        $this->assertResponseSuccess();

        $this->assertSame(0, $this->countActiveAuthenticationTokens($user->id));
        $this->assertSame($nToken, $this->countInactiveAuthenticationTokens($user->id));
    }

    public function testAuthJwtLogoutControllerWithPayload()
    {
        $user = UserFactory::make()->user()->persist();
        $this->createJwtTokenAndSetInHeader($user->id);
        $nToken = 3;
        $tokens = AuthenticationTokenFactory::make($nToken)
            ->active()
            ->type(AuthenticationToken::TYPE_REFRESH_TOKEN)
            ->userId($user->id)
            ->persist();

        $tokenToDeactivate = $tokens[0]->token;

        $this->postJson('/auth/jwt/logout.json', [
            'refresh_token' => $tokenToDeactivate,
        ]);
        $this->assertResponseSuccess();

        $this->assertSame($nToken - 1, $this->countActiveAuthenticationTokens($user->id));
        $this->assertSame(1, $this->countInactiveAuthenticationTokens($user->id));
        $this->assertFalse($this->AuthenticationTokens->isValid($tokenToDeactivate, $user->id));
    }

    private function countActiveAuthenticationTokens(string $userId): int
    {
        return $this->AuthenticationTokens->find()->where([
            'user_id' => $userId,
            'active' => true,
            'type' => AuthenticationToken::TYPE_REFRESH_TOKEN,
        ])->count();
    }

    private function countInactiveAuthenticationTokens(string $userId): int
    {
        return $this->AuthenticationTokens->find()->where([
            'user_id' => $userId,
            'active' => false,
            'type' => AuthenticationToken::TYPE_REFRESH_TOKEN,
        ])->count();
    }
}
