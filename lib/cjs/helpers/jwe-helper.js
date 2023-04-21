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
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptJWE = exports.decryptJWE = void 0;
const jose_1 = require("jose");
const constants_1 = require("../constants");
const common_1 = require("./common");
const signature_base_helper_1 = require("./signature-base-helper");
/**
 * Decrypts the input JWE string and returns the 'pkey' value from claims set.
 *
 * @param {string} jweString The JWE string.
 * @param {Config} config The input config.
 * @returns Promise<string> If the JWE decryption is successful, else returns Promise<undefined>.
 */
async function decryptJWE(jweString, config) {
    const masterKey = (0, common_1.readKey)(config.masterKey);
    const masterKeyBuffer = Buffer.from(masterKey, constants_1.constants.BASE64);
    const jwtDecryptResult = await (0, jose_1.jwtDecrypt)(jweString, masterKeyBuffer);
    if (jwtDecryptResult['payload'] && jwtDecryptResult['payload']['pkey']) {
        const pKey = jwtDecryptResult['payload']['pkey'];
        return constants_1.constants.KEY_START + pKey + constants_1.constants.KEY_END;
    }
}
exports.decryptJWE = decryptJWE;
/**
 * Generates JWE string.
 *
 * @param {Config} config The input config.
 * @returns {Promise<string>} jwe The JWE as string.
 */
async function encryptJWE(config) {
    const masterKey = (0, common_1.readKey)(config.masterKey);
    let publicKey = (0, common_1.readKey)(config.publicKey);
    publicKey = formatPublicKey(publicKey);
    const unixTimestamp = (0, signature_base_helper_1.getUnixTimestamp)();
    const masterKeyBuffer = Buffer.from(masterKey, constants_1.constants.BASE64);
    const jwe = await new jose_1.EncryptJWT(config.jwtPayload)
        .setProtectedHeader(config.jweHeaderParams)
        .setIssuedAt(unixTimestamp)
        .setNotBefore(unixTimestamp)
        .setExpirationTime(`${config.jwtExpiration}y`)
        .encrypt(masterKeyBuffer);
    return jwe;
}
exports.encryptJWE = encryptJWE;
/**
 * Removes beginning and end markers from the input public key.
 *
 * @param {string} key The public key.
 * @throws {Error} if the key format is invalid.
 */
function formatPublicKey(key) {
    try {
        const updatedKey = key.replace(constants_1.constants.KEY_PATTERN_START, '');
        return updatedKey.replace(constants_1.constants.KEY_PATTERN_END, '');
    }
    catch (exception) {
        throw new Error(`Invalid public key format`);
    }
}
