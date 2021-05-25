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

use App\Utility\UserAccessControl;
use Cake\Core\Configure;
use Cake\Validation\Validation;
use Firebase\JWT\JWT;
use InvalidArgumentException;

class GetJwtUserTokenSecretService extends JwtAbstractService
{
    public const SECRET_KEY_PATH = CONFIG . '/jwt.key';
    public const ALG = 'RS256';
    public const EXPIRATION = 60; // TODO: check the unit!!!
    public const HEADER = 'JwtAuthorization';

    /**
     * @var string
     */
    protected $keyPath = self::SECRET_KEY_PATH;

    /**
     * @param \App\Utility\UserAccessControl $uac The user successfully logging in.
     * @return string
     */
    public function getUserToken(UserAccessControl $uac): string
    {
        if (!Validation::uuid($uac->getId())) {
            throw new InvalidArgumentException(__('The resource identifier should be a valid UUID.'));
        }

        $privateKey = $this->readKeyFileContent();
        $payload = [
            'iss' => Configure::read('fullBaseUrl'), // TODO: check that this is O.K. for the cloud.
            'sub' => $uac->getId(),
            'exp' => time() + self::EXPIRATION,
        ];

        return JWT::encode($payload, $privateKey, self::ALG);
    }
}
