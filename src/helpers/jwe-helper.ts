/*
 * *
 *  * Copyright 2022 eBay Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *  http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 */

'use strict';

import { CompactJWEHeaderParameters, EncryptJWT, jwtDecrypt, JWTPayload } from 'jose';
import { Config } from '..';
import { constants } from '../constants';
import { readKey } from './common';
import { getUnixTimestamp } from './signature-base-helper';

/**
 * Decrypts the input JWE string and returns the 'pkey' value from claims set.
 * 
 * @param {string} jweString The JWE string.
 * @param {Config} config The input config.
 * @returns Promise<string> If the JWE decryption is successful, else returns Promise<undefined>.
 */
export async function decryptJWE(jweString: string, config: Config): Promise<string | undefined> {
    const masterKey: string = readKey(config.masterKey);

    const masterKeyBuffer: Buffer = Buffer.from(masterKey, constants.BASE64);
    const jwtDecryptResult: any = await jwtDecrypt(jweString, masterKeyBuffer)

    if (jwtDecryptResult['payload'] && jwtDecryptResult['payload']['pkey']) {
        const pKey = jwtDecryptResult['payload']['pkey'];
        return constants.KEY_START + pKey + constants.KEY_END;
    }
}

/**
 * Generates JWE string.
 * 
 * @param {Config} config The input config.
 * @returns {Promise<string>} jwe The JWE as string.
 */
export async function encryptJWE(config: Config): Promise<string> {
    const masterKey: string = readKey(config.masterKey);

    let publicKey = readKey(config.publicKey);
    publicKey = formatPublicKey(publicKey);

    const unixTimestamp = getUnixTimestamp();
    const masterKeyBuffer: Buffer = Buffer.from(masterKey, constants.BASE64);

    const jwe = await new EncryptJWT(config.jwtPayload as JWTPayload)
        .setProtectedHeader(config.jweHeaderParams as CompactJWEHeaderParameters)
        .setIssuedAt(unixTimestamp)
        .setNotBefore(unixTimestamp)
        .setExpirationTime(`${config.jwtExpiration}y`)
        .encrypt(masterKeyBuffer)

    return jwe;
}

/**
 * Removes beginning and end markers from the input public key.
 *
 * @param {string} key The public key.
 * @throws {Error} if the key format is invalid.
 */
function formatPublicKey(key: string): string {
    try {
        const updatedKey = key.replace(constants.KEY_PATTERN_START, '');
        return updatedKey.replace(constants.KEY_PATTERN_END, '');
    } catch (exception) {
        throw new Error(`Invalid public key format`);
    }
}