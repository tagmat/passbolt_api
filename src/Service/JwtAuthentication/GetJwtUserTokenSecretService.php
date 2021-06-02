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
namespace App\Service\JwtAuthentication;

use Cake\Core\Configure;
use Cake\Validation\Validation;
use Firebase\JWT\JWT;
use InvalidArgumentException;

class GetJwtUserTokenSecretService extends JwtAbstractService
{
    public const SECRET_KEY_PATH = CONFIG . '/jwt.key';
    public const ALG = 'RS256';
    public const HEADER = 'JwtAuthorization';
    public const USER_TOKEN_KEY = 'jwt_token';

    /**
     * @var string
     */
    protected $keyPath = self::SECRET_KEY_PATH;

    /**
     * @param string $userId The id of the user successfully logging in.
     * @return string
     * @throws \InvalidArgumentException if the userId is not a valid Uuid
     * @throws \App\Error\Exception\JWT\JwtKeyPairNotValidException if the JWT secret key is not readable.
     */
    public function getUserToken(string $userId): string
    {
        if (!Validation::uuid($userId)) {
            throw new InvalidArgumentException(__('The resource identifier should be a valid UUID.'));
        }

        $privateKey = $this->readKeyFileContent();
        $expirationDate = time() + Configure::read('passbolt.auth.token.jwt.expiry', 0);
        $payload = [
            'iss' => Configure::read('fullBaseUrl'), // TODO: check that this is O.K. for the cloud.
            'sub' => $userId,
            'exp' => $expirationDate,
        ];

        return JWT::encode($payload, $privateKey, self::ALG);
    }
}
