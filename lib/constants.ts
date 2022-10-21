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

export const constants = {
    BASE64: 'base64',
    COLON: ':',
    CONTENT_DIGEST_SHA256: 'sha-256=:',
    CONTENT_DIGEST_SHA512: 'sha-512=:',
    HEADERS: {
        APPLICATION_JSON: 'application/json',
        CONTENT_DIGEST: 'content-digest',
        SIGNATURE_INPUT: 'signature-input',
        SIGNATURE_KEY: 'x-ebay-signature-key',
        SIGNATURE: 'signature'
    },
    HTTP_STATUS_CODE: {
        NO_CONTENT: 204,
        OK: 200,
        BAD_REQUEST: 400,
        INTERNAL_SERVER_ERROR: 500
    },
    KEY_PATTERN_END: /\n-----END PUBLIC KEY-----/,
    KEY_PATTERN_START: /-----BEGIN PUBLIC KEY-----\n/,
    KEY_END: '\n-----END PUBLIC KEY-----',
    KEY_START: '-----BEGIN PUBLIC KEY-----\n',
    SHA_256: 'sha256',
    SHA_512: 'sha512',
    SIGNATURE_PREFIX: 'sig1=:',
    UTF8: 'utf8',
    X_EBAY_SIGNATURE: 'x-ebay-signature'
} as const;
