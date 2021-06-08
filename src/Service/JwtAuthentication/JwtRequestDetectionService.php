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

use App\Error\Exception\JWT\InvalidJwtKeyPairException;
use Cake\Utility\Hash;
use Psr\Http\Message\ServerRequestInterface;

class JwtRequestDetectionService
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request request
     * @return bool
     */
    public function mustUseJwt(ServerRequestInterface $request): bool
    {
        try {
            (new GetJwksPublicService())->getPublicKey();
        } catch (InvalidJwtKeyPairException $e) {
            return false;
        }

        $params = $request->getAttribute('params', null);
        if (isset($params)) {
            $controller = Hash::get($params, 'controller');
            $action = Hash::get($params, 'action');

            if ($controller === 'AuthJwtLogin' && $action === 'loginPost') {
                return true;
            }
        }

        if ($request->getHeaderLine('Authorization') !== '') {
            return true;
        }

        return false;
    }
}
