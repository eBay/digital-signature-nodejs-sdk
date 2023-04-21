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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateSignatureHeader = exports.validateSignatureKey = exports.generateSignatureKey = exports.generateSignatureInput = exports.generateSignature = void 0;
const crypto_1 = __importDefault(require("crypto"));
const constants_1 = require("../constants");
const jwe_helper_1 = require("./jwe-helper");
const signature_base_helper_1 = require("./signature-base-helper");
const common_1 = require("./common");
/**
 * Generates the x-ebay-signature-key header value for the input payload.
 *
 * @param {Config} config The input config.
 * @returns <Promise<string> The signature key value.
 */
async function generateSignatureKey(config) {
    const jwe = await (0, jwe_helper_1.encryptJWE)(config);
    return jwe;
}
exports.generateSignatureKey = generateSignatureKey;
;
/**
 * Generates the Signature-Input header value for the input payload.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns {string} the 'Signature-Input' header value.
 */
function generateSignatureInput(headers, config) {
    const unixTimestamp = (0, signature_base_helper_1.getUnixTimestamp)();
    let signatureInput = `sig1=(`;
    config.signatureParams.forEach((param) => {
        if (param === constants_1.constants.HEADERS.CONTENT_DIGEST &&
            !headers[constants_1.constants.HEADERS.CONTENT_DIGEST]) {
            return;
        }
        signatureInput += `"${param}" `;
    });
    signatureInput = signatureInput.trim() + `);created=${unixTimestamp}`;
    return signatureInput;
}
exports.generateSignatureInput = generateSignatureInput;
;
/**
 * Generates the 'Signature' header.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns {string} the signature header value.
 */
function generateSignature(headers, config) {
    const baseString = (0, signature_base_helper_1.generateBase)(headers, config);
    const privateKey = (0, common_1.readKey)(config.privateKey);
    // If algorithm is undefined, then it is dependent upon the private key type.
    const signatureBuffer = crypto_1.default.sign(undefined, Buffer.from(baseString), privateKey);
    let signature = signatureBuffer.toString(constants_1.constants.BASE64);
    return constants_1.constants.SIGNATURE_PREFIX + signature + constants_1.constants.COLON;
}
exports.generateSignature = generateSignature;
;
/**
 * Validates the input signature key (x-ebay-signature-key header value).
 *
 * @param {string} signatureKey the x-ebay-signature-key header value.
 * @param {Config} config The input config.
 * @returns Promise<string> the public key (pkey) value from JWT claims set.
 * @throws {Error} if the header generation fails.
 */
function validateSignatureKey(signatureKey, config) {
    try {
        return (0, jwe_helper_1.decryptJWE)(signatureKey, config);
    }
    catch (e) {
        throw new Error(`Error parsing JWE from x-ebay-signature-key header: ${e.message}`);
    }
    ;
}
exports.validateSignatureKey = validateSignatureKey;
/**
 * Validates the signature header value.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns Promise<boolean> True upon successful signature validation.
 * @throws Error if the Signature value is invalid.
 */
async function validateSignatureHeader(headers, config) {
    const signature = headers[constants_1.constants.HEADERS.SIGNATURE];
    const signatureKey = headers[constants_1.constants.HEADERS.SIGNATURE_KEY];
    if (!signatureKey) {
        throw new Error(`${constants_1.constants.HEADERS.SIGNATURE_KEY} header missing`);
    }
    if (!signature) {
        throw new Error(`${constants_1.constants.HEADERS.SIGNATURE} header missing`);
    }
    // Validate signature pattern
    const signaturePattern = new RegExp(".+=:(.+):");
    const signatureParts = signaturePattern.exec(signature);
    if (!signatureParts || signatureParts.length < 2) {
        throw new Error("Signature header invalid");
    }
    // Base64 decode
    const signatureBuffer = Buffer.from(signatureParts[1], constants_1.constants.BASE64);
    // Verify JWT
    const publicKey = await validateSignatureKey(signatureKey, config);
    const baseString = (0, signature_base_helper_1.calculateBase)(headers, config);
    // If algorithm is undefined, then it is dependent upon the public key type.
    const verificationResponse = crypto_1.default.verify(undefined, Buffer.from(baseString), publicKey, signatureBuffer);
    return verificationResponse;
}
exports.validateSignatureHeader = validateSignatureHeader;
