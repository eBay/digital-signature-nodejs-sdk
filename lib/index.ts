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
import { constants } from './constants';
import { Request, Response } from 'express';
import { generateDigestHeader, validateDigestHeader } from './helpers/digest-helper';
import { needsContentDigestValidation } from './helpers/common';
import {
    generateSignature,
    generateSignatureInput,
    generateSignatureKey,
    validateSignatureHeader
} from './helpers/signature-helper';
import { Config } from './types/Config';

/**
 * Generate signature headers and add it to the response.
 *
 * @param {Request} request The request object.
 * @param {Response} response The response object
 * @param {Config} config The input config.
 */
async function signMessage(request: Request, response: Response, config: Config): Promise<void> {
    try {
        const generatedHeaders: any = {};

        if (needsContentDigestValidation(request.body)) {
            const contentDigest = generateDigestHeader(
                request.body,
                config.digestAlgorithm
            );

            response.setHeader(constants.HEADERS.CONTENT_DIGEST, contentDigest);
            generatedHeaders[constants.HEADERS.CONTENT_DIGEST] = contentDigest
        }

        const signatureInput = generateSignatureInput(generatedHeaders, config);
        response.setHeader(constants.HEADERS.SIGNATURE_INPUT, signatureInput);

        // If JWE is not provided in the config, we generate it.
        let signatureKey: string = config.jwe;
        if (!signatureKey) {
            signatureKey = await generateSignatureKey(config);
        }

        response.setHeader(constants.HEADERS.SIGNATURE_KEY, signatureKey);
        generatedHeaders[constants.HEADERS.SIGNATURE_KEY] = signatureKey

        const signature = generateSignature(
            generatedHeaders,
            config
        );
        response.setHeader(constants.HEADERS.SIGNATURE, signature);
    } catch (e) {
        throw new Error(e);
    }
};

/**
 * Verifies the signature header for the given request
 *
 * @param {Request} request The request object.
 * @param {Config} config The input config.
 * @returns Promise<boolean> True upon successful signature validation.
 * */
async function validateSignature(request: Request, config: Config): Promise<boolean> {
    let response: boolean;

    try {
        //Validate
        if (!request || !request.headers[constants.HEADERS.SIGNATURE]) {
            throw new Error("Signature header is missing");
        }

        // Validate digest header, if needed.
        if (needsContentDigestValidation(request.body)) {
            const header = request.headers[constants.HEADERS.CONTENT_DIGEST] as string;
            validateDigestHeader(header, request.body);
        }

        // Verify signature
        const isSignatureValid: boolean = await validateSignatureHeader(
            request.headers,
            config
        );

        response = isSignatureValid;
    } catch (e) {
        // eslint-disable-next-line no-console
        console.error(e);
        response = e.message;
    }

    return response;
};

export {
    generateDigestHeader,
    generateSignature,
    generateSignatureInput,
    generateSignatureKey,
    signMessage,
    validateDigestHeader,
    validateSignature,
    validateSignatureHeader,
    Config
};