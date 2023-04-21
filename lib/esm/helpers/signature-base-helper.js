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
exports.getUnixTimestamp = exports.generateBase = exports.calculateBase = void 0;
const constants_1 = require("../constants");
/**
 * Generates the base string.
 *
 * @param {any} headers The HTTP request headers.
 * @param {Config} config The config.
 * @returns {string} baseString The base string.
 */
function generateBase(headers, config) {
    try {
        let baseString = "";
        const signatureParams = config.signatureParams;
        signatureParams.forEach((header) => {
            if (header === constants_1.constants.HEADERS.CONTENT_DIGEST &&
                !headers[constants_1.constants.HEADERS.CONTENT_DIGEST]) {
                return;
            }
            baseString += "\"";
            baseString += header.toLowerCase();
            baseString += "\": ";
            if (header.startsWith("@")) {
                switch (header.toLowerCase()) {
                    case "@method":
                        baseString += config.signatureComponents.method;
                        break;
                    case "@authority":
                        baseString += config.signatureComponents.authority;
                        break;
                    case "@target-uri":
                        baseString += config.signatureComponents.targetUri;
                        break;
                    case "@path":
                        baseString += config.signatureComponents.path;
                        break;
                    case "@scheme":
                        baseString += config.signatureComponents.scheme;
                        break;
                    case "@request-target":
                        baseString += config.signatureComponents.requestTarget;
                        break;
                    default:
                        throw new Error("Unknown pseudo header " + header);
                }
            }
            else {
                if (!headers[header]) {
                    throw new Error("Header " + header + " not included in message");
                }
                baseString += headers[header];
            }
            baseString += "\n";
        });
        baseString += "\"@signature-params\": ";
        let signatureInput = "";
        let signatureInputBuf = "";
        signatureInputBuf += "(";
        for (let i = 0; i < signatureParams.length; i++) {
            const param = signatureParams[i];
            signatureInputBuf += "\"";
            signatureInputBuf += param;
            signatureInputBuf += "\"";
            if (i < signatureParams.length - 1) {
                signatureInputBuf += " ";
            }
        }
        signatureInputBuf += ");created=";
        signatureInputBuf += getUnixTimestamp().toString();
        signatureInput = signatureInputBuf.toString();
        baseString = baseString + signatureInput;
        return baseString;
    }
    catch (e) {
        throw new Error(`Error calculating signature base: ${e.message}`);
    }
}
exports.generateBase = generateBase;
/**
 * Generates the base string for validation.
 *
 * @param {any} headers The HTTP request headers.
 * @param {Config} config The config.
 * @returns {string} baseString the base string.
 * @throws {Error} incase of an error.
 */
function calculateBase(headers, config) {
    try {
        const signatureInputHeader = headers[constants_1.constants.HEADERS.SIGNATURE_INPUT];
        if (!signatureInputHeader || signatureInputHeader.length == 0) {
            throw new Error("Signature-Input header missing");
        }
        // Validate signature pattern
        const signatureInputPattern = new RegExp(".+=(\\((.+)\\);created=(\\d+)(;keyid=.+)?)");
        const signatureInputParts = signatureInputPattern.exec(signatureInputHeader);
        if (!signatureInputParts || signatureInputParts.length < 3) {
            throw new Error("Invalid Signature-Input. Make sure it's of format: .+=\\(.+\\;created=\\d+)");
        }
        const signatureInput = signatureInputParts[2].replaceAll("\"", "");
        const signatureParams = signatureInput.split(" ");
        let baseString = '';
        signatureParams.forEach((header) => {
            baseString += "\"";
            baseString += header.toLowerCase();
            baseString += "\": ";
            if (header.startsWith("@")) {
                switch (header.toLowerCase()) {
                    case "@method":
                        baseString += config.signatureComponents.method;
                        break;
                    case "@authority":
                        baseString += config.signatureComponents.authority;
                        break;
                    case "@target-uri":
                        baseString += config.signatureComponents.targetUri;
                        break;
                    case "@path":
                        baseString += config.signatureComponents.path;
                        break;
                    case "@scheme":
                        baseString += config.signatureComponents.scheme;
                        break;
                    case "@request-target":
                        baseString += config.signatureComponents.requestTarget;
                        break;
                    default:
                        throw new Error("Unknown pseudo header " + header);
                }
            }
            else {
                if (!headers[header]) {
                    throw new Error("Header " + header + " not included in message");
                }
                baseString += headers[header];
            }
            baseString += "\n";
        });
        baseString += "\"@signature-params\": ";
        baseString += signatureInputParts[1];
        return baseString;
    }
    catch (e) {
        throw new Error(`Error calculating base: ${e.message}`);
    }
}
exports.calculateBase = calculateBase;
/**
 * Returns the current UNIX timestamp.
 *
 * @returns {number} The unix timestamp.
 */
function getUnixTimestamp() {
    return Math.floor(Date.now() / 1000);
}
exports.getUnixTimestamp = getUnixTimestamp;
