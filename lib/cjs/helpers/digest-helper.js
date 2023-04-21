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
exports.validateDigestHeader = exports.generateDigestHeader = void 0;
const crypto_1 = __importDefault(require("crypto"));
const constants_1 = require("../constants");
/**
 * Generates the 'Content-Digest' header value for the input payload.
 *
 * @param {Buffer} payload The request payload.
 * @param {string} cipher The algorithm used to calculate the digest.
 * @returns {string} contentDigest The 'Content-Digest' header value.
 */
function generateDigestHeader(payload, cipher) {
    let contentDigest = '';
    // Validate the input payload
    if (!payload) {
        return contentDigest;
    }
    // Calculate the SHA-256 digest
    const hash = crypto_1.default.createHash(cipher)
        .update(payload)
        .digest(constants_1.constants.BASE64);
    const algo = cipher === constants_1.constants.SHA_512 ? constants_1.constants.CONTENT_DIGEST_SHA512 :
        constants_1.constants.CONTENT_DIGEST_SHA256;
    contentDigest = algo + hash + constants_1.constants.COLON;
    return contentDigest;
}
exports.generateDigestHeader = generateDigestHeader;
;
/**
 * Validates the 'Content-Digest' header value.
 *
 * @param {string} contentDigestHeader The Content-Digest header value.
 * @param {Buffer} body The HTTP request body.
 * @throws {Error} If the Content-Digest header value is invalid.
 */
function validateDigestHeader(contentDigestHeader, body) {
    if (!contentDigestHeader) {
        throw new Error("Content-Digest header missing");
    }
    // Validate
    const contentDigestPattern = new RegExp("(.+)=:(.+):");
    const contentDigestParts = contentDigestPattern.exec(contentDigestHeader);
    if (!contentDigestParts || contentDigestParts.length == 0) {
        throw new Error("Content-digest header invalid");
    }
    const cipher = contentDigestParts[1];
    if (cipher !== "sha-256" && cipher !== "sha-512") {
        throw new Error("Invalid cipher " + cipher);
    }
    const algorithm = cipher === "sha-256" ? constants_1.constants.SHA_256 : constants_1.constants.SHA_512;
    const newDigest = generateDigestHeader(body, algorithm);
    if (newDigest !== contentDigestHeader) {
        throw new Error("Content-Digest value is invalid. Expected body digest is: "
            + newDigest);
    }
}
exports.validateDigestHeader = validateDigestHeader;
