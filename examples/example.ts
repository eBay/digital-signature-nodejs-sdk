/* eslint-disable no-console */
/* eslint-disable max-len */
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

import bodyParser from 'body-parser';
import { constants } from '../lib/constants';
import express, { Request, Response } from 'express';
import * as DigitalSignatureSDK from '../lib/index';
import { needsContentDigestValidation } from '../lib/helpers/common';

const config: DigitalSignatureSDK.Config = require('./example-config.json');
const configFull: DigitalSignatureSDK.Config = require('./example-config-full.json');

const app = express();
const PORT = process.env.PORT || 8080;
const options = {
    inflate: true,
    limit: '100kb',
    type: 'application/*'
}

app.use(bodyParser.raw(options));

/**
 * This endpoint uses `example-config.json` with `signMessage()` to sign the incoming request.
 */
app.post('/sign-request', async (req: Request, res: Response) => {
    try {
        await DigitalSignatureSDK.signMessage(req, res, config);
        res.status(constants.HTTP_STATUS_CODE.OK).send();
    } catch (ex) {
        console.error(ex);
        res.status(constants.HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send();
    };
});

/**
 * This endpoint uses `example-config-full.json` and individual methods to generate signature.
 */
app.post('/sign', async (req: Request, res: Response) => {
    try {
        const generatedHeaders: any = {};

        const payloadBuffer: Buffer = Buffer.from(req.body);

        if (needsContentDigestValidation(req.body)) {
            const contentDigest = DigitalSignatureSDK.generateDigestHeader(
                payloadBuffer,
                configFull.digestAlgorithm
            );
            generatedHeaders[constants.HEADERS.CONTENT_DIGEST] = contentDigest
        }

        const signatureInput = DigitalSignatureSDK.generateSignatureInput(generatedHeaders, configFull);
        generatedHeaders[constants.HEADERS.SIGNATURE_INPUT] = signatureInput

        const signatureKey = await DigitalSignatureSDK.generateSignatureKey(configFull);
        generatedHeaders[constants.HEADERS.SIGNATURE_KEY] = signatureKey

        const signature = DigitalSignatureSDK.generateSignature(generatedHeaders, configFull);
        generatedHeaders[constants.HEADERS.SIGNATURE] = signature

        res.status(constants.HTTP_STATUS_CODE.OK).send(generatedHeaders);
    } catch (ex) {
        console.error(ex);
        res.status(constants.HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send();
    };
});

/**
 * This endpoint uses `example-config-full.json` with `validateSignature()` to validate the signature.
 */
app.post('/validate-request', async (req: Request, res: Response) => {
    try {
        let response: boolean = await DigitalSignatureSDK.validateSignature(req, configFull);

        if (true === response) {
            res.status(constants.HTTP_STATUS_CODE.OK).send();
        } else {
            console.error(`Signature verification failure`);
            res.status(constants.HTTP_STATUS_CODE.BAD_REQUEST).send();
        }
    } catch (ex) {
        console.error(ex);
        res.status(constants.HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send();
    };
});

/**
 * This endpoint uses `example-config-full.json` and individual methods to validate the signature.
 */
app.post('/validate', async (req: Request, res: Response) => {
    try {
        // Validate digest header, if needed.
        if (needsContentDigestValidation(req.method)) {
            const header = req.headers[constants.HEADERS.CONTENT_DIGEST] as string;
            DigitalSignatureSDK.validateDigestHeader(header, req.body);
        }

        // Validate signature header
        let response: boolean = await DigitalSignatureSDK.validateSignatureHeader(
            req.headers,
            configFull
        );

        if (true === response) {
            res.status(constants.HTTP_STATUS_CODE.OK).send();
        } else {
            console.error(`Signature verification failure`);
            res.status(constants.HTTP_STATUS_CODE.BAD_REQUEST).send();
        }
    } catch (ex) {
        console.error(ex);
        res.status(constants.HTTP_STATUS_CODE.INTERNAL_SERVER_ERROR).send();
    };
});

app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Listening at http://localhost:${PORT}`);
});
